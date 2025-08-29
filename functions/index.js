import JSEncrypt from 'jsencrypt'

const config = {
    alias: 'dx4600', // 绿联UGLinkID
    username: "guest", // 绿联账号
    password: "jL6w8uM4knMyHQr0", // 绿联密码
    port: 5244 // 容器端口
}

const kv = {
    key: config.alias + ':' + config.port,
    async get() {
        const value = await nas.get(this.key)
        if (value == null) {
            return null
        }
        return JSON.parse(value)
    },
    async set(value) {
        await nas.put(this.key, JSON.stringify(value))
    }
}

const getUGreenLink = async ctx => {
    const aliasUrl = new URL('https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias')
    const response = await fetch(aliasUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alias: config.alias})
    })
    const res = await response.json()
    return 'https://' + config.alias + '.' + res.data.relayDomain
}

const getPublicKey = async ctx => {
    const url = new URL(ctx.link + '/ugreen/v1/verify/check')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            username: config.username
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const base64Str = response.headers.get('x-rsa-token')
    return atob(base64Str)
}


const getPassword = async ctx => {
    const encryptor = new JSEncrypt()
    encryptor.setPublicKey(ctx.publicKey)
    return encryptor.encrypt(config.password)
}

const login = async ctx => {
    const url = new URL(ctx.link + '/ugreen/v1/verify/login')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            is_simple: true,
            keepalive: true,
            otp: true,
            username: config.username,
            password: ctx.password
        }),
        headers: {
            'Content-Type': 'application/json'
        }
    })
    const json = await response.json()
    return json.data
}


const getDockerToken = async ctx => {
    const url = new URL(ctx.link + '/ugreen/v1/gateway/proxy/dockerToken')
    url.searchParams.set('token', ctx.token)
    url.searchParams.set('port', config.port)
    const response = await fetch(url)
    const json = await response.json()
    return json.data['redirect_url']
}

const getProxyInfo = async ctx => {
    const response = await fetch(ctx.dockerToken, {
        method: 'GET',
        redirect: 'manual',
    })
    const cookieStr = response.headers.get('set-cookie')
    const cookies = new Cookies(cookieStr, true)
    const origin = new URL(ctx.dockerToken).origin
    const token = cookies.get('ugreen-proxy-token').value
    return {origin, token}
}


const proxy = async (request, origin, token) => {
    const requestUrl = new URL(request.url)
    const requestOrigin = requestUrl.origin
    
    const target = request.url.replace(requestOrigin, origin)
    const targetUrl = new URL(target)
    const targetHeaders = new Headers(request.headers)
    targetHeaders.set('host', targetUrl.host)
    
    const cookies = getCookies(targetHeaders.get('cookie'))
    cookies['ugreen-proxy-token'] = token
    targetHeaders.set('cookie', getCookieStr(cookies))
    
    const response =  await fetch(targetUrl, {
        method: request.method,
        headers: targetHeaders,
        body: request.body,
        redirect: 'manual'
    })
    
    if (Array.from(response.headers.keys()).length === 1) {
        if (response.headers.get('content-type') === 'text/html; charset=UTF-8') {
            const html = await response.text()
            if (html.includes('https://www.ug.link/errorPage')) {
                throw new Error('访问错误')
            }
        }
    }
    
    return response
}



const getCookies = cookieStr => {
    const cookieMap = {}
    if (cookieStr == null) {
        return cookieMap
    }
    const cookieArr = cookieStr.split('; ')
    for (let cookie of cookieArr) {
        const cookieObj = cookie.split('=')
        cookieMap[cookieObj[0]] = decodeURIComponent(cookieObj[1])
    }
    return cookieMap
}

const getCookieStr = cookieMap => {
    const cookieArr = []
    for (let key of Object.keys(cookieMap)) {
        cookieArr.push(key + '=' + encodeURIComponent(cookieMap[key]))
    }
    return cookieArr.join('; ')
}


export async function onRequest(context) {
    const request = context.request
    
    try {
        const cache = await kv.get()
        if (cache) {
            const response =  await proxy(request, cache.origin, cache.token)
            response.headers.set('x-edge-kv', 'hit')
            return response
        }
    } catch (error) {
        console.log('缓存访问出错')
    }
    
    try {
        const ctx = {}
        ctx.link = await getUGreenLink(ctx)
        ctx.publicKey = await getPublicKey(ctx)
        ctx.password = await getPassword(ctx)
        const loginInfo = await login(ctx)
        ctx.token = loginInfo.token
        ctx.dockerToken = await getDockerToken(ctx)
        const proxyInfo = await getProxyInfo(ctx)
        ctx.proxyOrigin = proxyInfo.origin
        ctx.proxyToken = proxyInfo.token
        const response = await proxy(request, ctx.proxyOrigin, ctx.proxyToken)
        response.headers.set('x-edge-kv', 'miss')
        await kv.set({origin: ctx.proxyOrigin, token: ctx.proxyToken})
        return response
    } catch (error) {
        return new Response('访问出错', {status: 500})
    }
    
}

