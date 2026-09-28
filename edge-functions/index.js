import JSEncrypt from 'jsencrypt'

// 改造 Database：显式接收 kv 实例，防止全局变量作用域缺失
const Database = {
    async getObject(kv, key) {
        if (!kv) return null
        const value = await kv.get(key)
        if (value == null) {
            return null
        }
        return JSON.parse(value)
    },
    async setObject(kv, key, value) {
        if (!kv) return
        if (value == null) {
            await kv.delete(key)
        } else {
            await kv.put(key, JSON.stringify(value))
        }
    }
}

const CookieHelper = {
    getSetCookieObject(response) {
        const cookieObject = {}
        const setCookie = response.headers.getSetCookie()
        if (setCookie) {
            for (let cookieStr of setCookie) {
                const [key, value] = cookieStr.split(';')[0].split('=')
                cookieObject[key] = value
            }
        }
        return cookieObject
    },
    getCookieObject(cookieStr) {
        const cookieObject = {}
        if (cookieStr == null) {
            return cookieObject
        }
        const cookieArr = cookieStr.split('; ')
        for (let cookie of cookieArr) {
            const cookieObj = cookie.split('=')
            cookieObject[cookieObj[0]] = decodeURIComponent(cookieObj[1])
        }
        return cookieObject
    },
    getCookieStr(cookieObject) {
        const cookieArr = []
        if (cookieObject) {
            for (let key of Object.keys(cookieObject)) {
                cookieArr.push(key + '=' + encodeURIComponent(cookieObject[key]))
            }
        }
        return cookieArr.join('; ')
    }
}

const getUGreenLink = async ctx => {
    const config = ctx.config
    if (!config.alias) throw new Error('缺少环境变量: UG_ALIAS')
    const aliasUrl = new URL('https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias')
    const response = await fetch(aliasUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alias: config.alias})
    })
    const res = await response.json()
    if (!res.data || !res.data.relayDomain) {
        throw new Error(`绿联中继域名获取失败: ${JSON.stringify(res)}`)
    }
    return 'https://' + config.alias + '.' + res.data.relayDomain
}

const getPublicKey = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/verify/check')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            username: config.username
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const base64Str = response.headers.get('x-rsa-token')
    if (!base64Str) throw new Error('未能获取到 x-rsa-token 响应头')
    return atob(base64Str)
}

const getPassword = async ctx => {
    const config = ctx.config
    if (!config.password) throw new Error('缺少环境变量: UG_PASSWORD')
    const encryptor = new JSEncrypt()
    encryptor.setPublicKey(ctx.publicKey)
    return encryptor.encrypt(config.password)
}

const login = async ctx => {
    const config = ctx.config
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
        headers: {'Content-Type': 'application/json'}
    })
    const json = await response.json()
    if (!json.data || !json.data.token) {
        throw new Error(`绿联登录认证失败: ${JSON.stringify(json)}`)
    }
    return json.data
}

const getDockerToken = async ctx => {
    const config = ctx.config
    if (!config.port) throw new Error('缺少环境变量: UG_PORT')
    const url = new URL(ctx.link + '/ugreen/v1/gateway/proxy/dockerToken')
    url.searchParams.set('token', ctx.token)
    url.searchParams.set('port', config.port)
    const response = await fetch(url)
    const json = await response.json()
    if (!json.data || !json.data['redirect_url']) {
        throw new Error(`获取 Docker 代理重定向失败: ${JSON.stringify(json)}`)
    }
    return json.data['redirect_url']
}

const getProxyInfo = async ctx => {
    const response = await fetch(ctx.dockerToken, {
        method: 'GET',
        redirect: 'manual',
    })
    const origin = new URL(ctx.dockerToken).origin
    const cookieObject = CookieHelper.getSetCookieObject(response)
    const token = cookieObject['ugreen-proxy-token']
    if (!token) throw new Error('未能从重定向响应中提取 ugreen-proxy-token')
    return {origin, token}
}

const proxy = async (request, origin, token) => {
    const requestUrl = new URL(request.url)
    const requestOrigin = requestUrl.origin
    
    const target = request.url.replace(requestOrigin, origin)
    const targetUrl = new URL(target)
    const targetHeaders = new Headers(request.headers)
    targetHeaders.set('host', targetUrl.host)
    
    const cookieObject = CookieHelper.getCookieObject(request.headers.get('cookie'))
    cookieObject['ugreen-proxy-token'] = token
    targetHeaders.set('cookie', CookieHelper.getCookieStr(cookieObject))
    
    const response = await fetch(targetUrl, {
        method: request.method,
        headers: targetHeaders,
        body: request.body,
        redirect: 'manual'
    })
    
    if (Array.from(response.headers.keys()).length === 1) {
        if (response.headers.get('content-type') === 'text/html; charset=UTF-8') {
            const clone = response.clone()
            const html = await clone.text()
            if (html.includes('https://www.ug.link/errorPage')) {
                throw new Error('目标端返回了绿联错误页 (errorPage)')
            }
        }
    }
    
    return response
}

export async function onRequest(context) {
    const request = context.request
    const env = context.env || {}
    // 兼容获取 KV 句柄：优先从 env 取，其次尝试全局变量
    const kvStore = env.nas || (typeof nas !== 'undefined' ? nas : null)

    const config = {
        alias: env.UG_ALIAS,
        username: env.UG_USERNAME,
        password: env.UG_PASSWORD,
        port: env.UG_PORT
    }

    // 关键修正：EdgeOne KV Key 严禁包含冒号，改为下划线连接
    const key = `${config.alias || 'unknown'}_${config.port || '0'}`

    try {
        const cache = await Database.getObject(kvStore, key)
        if (cache) {
            const response = await proxy(request, cache.origin, cache.token)
            response.headers.set('x-edge-kv', 'hit')
            return response
        }
    } catch (error) {
        console.log('缓存命中时转发异常:', error.message)
    }

    const ctx = { config }
    try {
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
        
        // 尝试写入 KV 缓存
        await Database.setObject(kvStore, key, {origin: ctx.proxyOrigin, token: ctx.proxyToken})
        return response
    } catch (error) {
        console.error('执行流程出错:', error)
        // 调试阶段直接回显详细报错原因，排查完毕后可改回简单文本
        return new Response(`访问出错: ${error.message}`, {
            status: 500,
            headers: {'Content-Type': 'text/plain; charset=utf-8'}
        })
    }
}
