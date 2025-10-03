import { defineStore } from 'pinia';

const useSessionStore = defineStore("Session", {
  state: () => ({
    sessions: []
  }),
  actions: {
    async setSessions(session) {
      const tempSession = {
        id: `temp-${Date.now()}`,
        // temporary ID
        title: session.title,
        userId: session.userId,
        createdAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      this.sessions.push(tempSession);
    },
    async fetchSessions() {
      try {
        const data = await $fetch("/api/sessions");
        this.sessions = data;
      } catch (err) {
        console.error("Failed to fetch sessions:", err);
      }
    }
  }
});

export { useSessionStore as u };
//# sourceMappingURL=sessions-Ch2qXTsx.mjs.map
