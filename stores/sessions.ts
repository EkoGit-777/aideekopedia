import { defineStore } from 'pinia'

interface State {
  sessions: SessionType[]
}

export const useSessionStore = defineStore('Session', {
  state: (): State => ({
    sessions: [],
  }),
  actions: {
    async setSessions(session: Omit<SessionType, 'id' | 'createdAt'>) {
      // try {
      //   // Try to save in DB
      //   const newSession = await $fetch<SessionType>('/api/sessions', {
      //     method: 'POST',
      //     body: session,
      //   })
      //   this.sessions.push(newSession)
      // } catch (err) {
      //   console.error('Failed to save session in DB:', err)

        // Fallback: push a local-only session
        const tempSession: SessionType = {
          id: `temp-${Date.now()}`, // temporary ID
          title: session.title,
          userId: session.userId,
          createdAt: new Date().toISOString(),
        }
        this.sessions.push(tempSession)
      // }
    },

    async fetchSessions() {
      try {
        const data = await $fetch<SessionType[]>('/api/sessions')
        this.sessions = data
      } catch (err) {
        console.error('Failed to fetch sessions:', err)
      }
    },
  },
})