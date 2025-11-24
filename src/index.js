import dayjs from 'dayjs'
import { Router } from 'itty-router'
import Cookies from 'cookie'
import jwt from '@tsndr/cloudflare-worker-jwt'
import { queryNote, MD5, checkAuth, genRandomStr, returnPage, returnJSON, saltPw, getI18n } from './helper'
import { SECRET } from './constant'

// init
const router = Router()

// 获取所有笔记列表
async function getNoteList() {
    try {
        const list = await NOTES.list()
        const notes = []
        
        for (const key of list.keys) {
            try {
                const { metadata } = await queryNote(key.name)
                notes.push({
                    name: key.name,
                    title: decodeURIComponent(key.name),
                    updateAt: metadata?.updateAt ? dayjs.unix(metadata.updateAt).format('YYYY-MM-DD HH:mm') : 'Unknown',
                    hasPassword: !!metadata?.pw,
                    isShared: metadata?.share
                })
            } catch (error) {
                console.error(`Error processing note ${key.name}:`, error)
                // 如果单个笔记处理失败，继续处理其他笔记
                notes.push({
                    name: key.name,
                    title: decodeURIComponent(key.name),
                    updateAt: 'Unknown',
                    hasPassword: false,
                    isShared: false
                })
            }
        }
        
        // 按更新时间倒序排列
        return notes.sort((a, b) => {
            if (a.updateAt === 'Unknown') return 1
            if (b.updateAt === 'Unknown') return -1
            if (a.updateAt === 'Unknown' && b.updateAt === 'Unknown') return 0
            return new Date(b.updateAt) - new Date(a.updateAt)
        })
    } catch (error) {
        console.error('Get note list error:', error)
        return []
    }
}

// 保持原来的根路由行为，不修改它
router.get('/', ({ url }) => {
    const newHash = genRandomStr(3)
    // redirect to new page
    return Response.redirect(`${url}${newHash}`, 302)
})

// 新增目录路由
router.get('/directory', async (request) => {
    const lang = getI18n(request)
    
    try {
        const notes = await getNoteList()
        
        return returnPage('NoteList', {
            lang,
            title: 'Notes Directory',
            notes,
            noteCount: notes.length
        })
    } catch (error) {
        console.error('Directory page error:', error)
        return returnPage('Error', { 
            lang, 
            title: 'Error',
            message: 'Failed to load note directory'
        })
    }
})

// API: 获取笔记列表 (JSON格式)
router.get('/api/notes', async (request) => {
    try {
        const notes = await getNoteList()
        return returnJSON(0, {
            notes,
            count: notes.length
        })
    } catch (error) {
        console.error('API get notes error:', error)
        return returnJSON(10005, 'Get note list failed!')
    }
})

router.get('/share/:md5', async (request) => {
    const lang = getI18n(request)
    const { md5 } = request.params
    const path = await SHARE.get(md5)

    if (!!path) {
        const { value, metadata } = await queryNote(path)

        return returnPage('Share', {
            lang,
            title: decodeURIComponent(path),
            content: value,
            ext: metadata,
        })
    }

    return returnPage('Page404', { lang, title: '404' })
})

router.get('/:path', async (request) => {
    const lang = getI18n(request)

    const { path } = request.params
    const title = decodeURIComponent(path)

    const cookie = Cookies.parse(request.headers.get('Cookie') || '')

    const { value, metadata } = await queryNote(path)

    if (!metadata.pw) {
        return returnPage('Edit', {
            lang,
            title,
            content: value,
            ext: metadata,
        })
    }

    const valid = await checkAuth(cookie, path)
    if (valid) {
        return returnPage('Edit', {
            lang,
            title,
            content: value,
            ext: metadata,
        })
    }

    return returnPage('NeedPasswd', { lang, title })
})

router.post('/:path/auth', async request => {
    const { path } = request.params
    if (request.headers.get('Content-Type') === 'application/json') {
        const { passwd } = await request.json()

        const { metadata } = await queryNote(path)

        if (metadata.pw) {
            const storePw = await saltPw(passwd)

            if (metadata.pw === storePw) {
                const token = await jwt.sign({ path }, SECRET)
                return returnJSON(0, {
                    refresh: true,
                }, {
                    'Set-Cookie': Cookies.serialize('auth', token, {
                        path: `/${path}`,
                        expires: dayjs().add(7, 'day').toDate(),
                        httpOnly: true,
                    })
                })
            }
        }
    }

    return returnJSON(10002, 'Password auth failed!')
})

router.post('/:path/pw', async request => {
    const { path } = request.params
    if (request.headers.get('Content-Type') === 'application/json') {
        const cookie = Cookies.parse(request.headers.get('Cookie') || '')
        const { passwd } = await request.json()

        const { value, metadata } = await queryNote(path)
        const valid = await checkAuth(cookie, path)

        if (!metadata.pw || valid) {
            const pw = passwd ? await saltPw(passwd) : undefined
            try {
                await NOTES.put(path, value, {
                    metadata: {
                        ...metadata,
                        pw,
                    },
                })

                return returnJSON(0, null, {
                    'Set-Cookie': Cookies.serialize('auth', '', {
                        path: `/${path}`,
                        expires: dayjs().subtract(100, 'day').toDate(),
                        httpOnly: true,
                    })
                })
            } catch (error) {
                console.error(error)
            }
        }

        return returnJSON(10003, 'Password setting failed!')
    }
})

router.post('/:path/setting', async request => {
    const { path } = request.params
    if (request.headers.get('Content-Type') === 'application/json') {
        const cookie = Cookies.parse(request.headers.get('Cookie') || '')
        const { mode, share } = await request.json()

        const { value, metadata } = await queryNote(path)
        const valid = await checkAuth(cookie, path)

        if (!metadata.pw || valid) {
            try {
                await NOTES.put(path, value, {
                    metadata: {
                        ...metadata,
                        ...mode !== undefined && { mode },
                        ...share !== undefined && { share },
                    },
                })

                const md5 = await MD5(path)
                if (share) {
                    await SHARE.put(md5, path)
                    return returnJSON(0, md5)
                }
                if (share === false) {
                    await SHARE.delete(md5)
                }

                return returnJSON(0)
            } catch (error) {
                console.error(error)
            }
        }

        return returnJSON(10004, 'Update Setting failed!')
    }
})

router.post('/:path', async request => {
    const { path } = request.params
    const { value, metadata } = await queryNote(path)

    const cookie = Cookies.parse(request.headers.get('Cookie') || '')
    const valid = await checkAuth(cookie, path)

    if (!metadata.pw || valid) {
        // OK
    } else {
        return returnJSON(10002, 'Password auth failed! Try refreshing this page if you had just set a password.')
    }

    const formData = await request.formData();
    const content = formData.get('t')

    try {
        if (content?.trim()){
            // 有值修改
            await NOTES.put(path, content, {
                metadata: {
                    ...metadata,
                    updateAt: dayjs().unix(),
                },
            })
        }else{
            // 无值删除
            await NOTES.delete(path)
        }

        return returnJSON(0)
    } catch (error) {
        console.error(error)
    }

    return returnJSON(10001, 'KV insert fail!')
})

router.all('*', (request) => {
    const lang = getI18n(request)
    return returnPage('Page404', { lang, title: '404' })
})

addEventListener('fetch', event => {
    event.respondWith(router.handle(event.request))
})
