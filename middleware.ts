import { type NextRequest, NextResponse } from "next/server"
import { createServerClient } from "@supabase/ssr"

export async function middleware(request: NextRequest) {
  // Skip middleware for API routes and static files
  if (request.nextUrl.pathname.startsWith('/api/') ||
      request.nextUrl.pathname.startsWith('/_next/') ||
      request.nextUrl.pathname.includes('.')) {
    return NextResponse.next()
  }

  try {
    const supabaseResponse = NextResponse.next({
      request,
    })

    const url = process.env.NEXT_PUBLIC_SUPABASE_URL
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

    if (!url || !key) {
      console.error('Supabase environment variables not set')
      return supabaseResponse
    }

    const supabase = createServerClient(url, key, {
      cookies: {
        getAll() {
          return request.cookies.getAll()
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value, options }) => {
            supabaseResponse.cookies.set(name, value, options)
          })
        },
      },
    })

    return supabaseResponse
  } catch (error) {
    console.error('Middleware error:', error)
    return NextResponse.next()
  }
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.svg).*)"],
}
