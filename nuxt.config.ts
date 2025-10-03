// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2025-07-15',
  devtools: { enabled: true },
  modules: [
    '@unocss/nuxt',
    // '@logto/nuxt',
    '@pinia/nuxt'
  ],
  css: ['~/assets/tailwind.css'],
  runtimeConfig: {
    // logto: {
    //   endpoint: process.env.LOGTO_ENDPOINT,
    //   appId: process.env.LOGTO_APP_ID,
    //   appSecret: process.env.LOGTO_APP_SECRET,
    //   cookieEncryptionKey: process.env.LOGTO_COOKIE_ENCRYPTION_KEY,
    // },
    googleGeminiApiKey: process.env.GOOGLE_GENERATIVE_AI_API_KEY,
  },
  logto: {
    pathnames: {
      signIn: '/sign-in',
      signOut: '/sign-out',
      callback: '/callback',
    },
  },
  vite: {
    server: {
      allowedHosts: [
        'localhost',
        '127.0.0.1',
        'devserver-main--dulcet-mochi-d7b54b.netlify.app',
        'dulcet-mochi-d7b54b.netlify.app',
        'devserver-main--stupendous-liger-9269b4.netlify.app',
        'stupendous-liger-9269b4.netlify.app'
      ],
    },
  }
})
