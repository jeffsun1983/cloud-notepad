import dayjs from 'dayjs'
import { Router } from 'itty-router'
import Cookies from 'cookie'
import jwt from '@tsndr/cloudflare-worker-jwt'
import { queryNote, MD5, checkAuth, genRandomStr, returnPage, returnJSON, saltPw, getI18n } from './helper'
import { SECRET } from './constant'

// init
const router = Router()

// 安全获取笔记列表函数
async function getNoteList() {
    try {
        // 使用安全的KV列表获取
        const list = await NOTES.list()
        const notes = []
        
        // 并行处理所有笔记，提高性能
        const notePromises = list.keys.map(async (key) => {
            try {
                const { metadata } = await queryNote(key.name)
                return {
                    name: key.name,
                    title: decodeURIComponent(key.name),
                    updateAt: metadata?.updateAt ? dayjs.unix(metadata.updateAt).format('YYYY-MM-DD HH:mm') : 'Unknown',
                    hasPassword: !!metadata?.pw,
                    isShared: !!metadata?.share
                }
            } catch (error) {
                // 单个笔记出错不影响整个列表
                console.warn(`Failed to process note ${key.name}:`, error)
                return {
                    name: key.name,
                    title: decodeURIComponent(key.name),
                    updateAt: 'Unknown',
                    hasPassword: false,
                    isShared: false
                }
            }
        })
        
        const notes = await Promise.all(notePromises)
        
        // 安全排序
        return notes.sort((a, b) => {
            if (a.updateAt === 'Unknown' && b.updateAt === 'Unknown') return 0
            if (a.updateAt === 'Unknown') return 1
            if (b.updateAt === 'Unknown') return -1
            
            try {
                return new Date(b.updateAt).getTime() - new Date(a.updateAt).getTime()
            } catch {
                return 0
            }
        })
    } catch (error) {
        console.error('Failed to get note list:', error)
        return [] // 始终返回数组，避免undefined
    }
}

// 主页显示笔记目录
router.get('/', async (request) => {
    const lang = getI18n(request)
    
    try {
        const notes = await getNoteList()
        
        // 确保notes是数组
        const safeNotes = Array.isArray(notes) ? notes : []
        
        return returnPage('NoteList', {
            lang,
            title: 'Notes Directory',
            notes: safeNotes,
            noteCount: safeNotes.length
        })
    } catch (error) {
        console.error('Home page directory error:', error)
        
        // 出错时回退到创建新笔记
        const newHash = genRandomStr(3)
        return Response.redirect(`${request.url}${newHash}`, 302)
    }
})

// 备用目录页面
router.get('/directory', async (request) => {
    const lang = getI18n(request)
    
    try {
        const notes = await getNoteList()
        const safeNotes = Array.isArray(notes) ? notes : []
        
        return returnPage('NoteList', {
            lang,
            title: 'Notes Directory',
            notes: safeNotes,
            noteCount: safeNotes.length
        })
    } catch (error) {
        console.error('Directory page error:', error)
        
        // 显示友好的错误页面
        return returnPage('Error', {
            lang,
            title: 'Error',
            message: 'Unable to load note directory at this time.'
        })
    }
})

// 创建新笔记的路由
router.get('/new', (request) => {
    const newHash = genRandomStr(3)
    return Response.redirect(`${request.url}${newHash}`, 302)
})

// API端点获取笔记列表
router.get('/api/notes', async (request) => {
    try {
        const notes = await getNoteList()
        const safeNotes = Array.isArray(notes) ? notes : []
        
        return returnJSON(0, {
            notes: safeNotes,
            count: safeNotes.length
        })
    } catch (error) {
        console.error('API notes error:', error)
        return returnJSON(10005, 'Failed to retrieve notes list')
    }
})

// 以下保持原有路由不变
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
