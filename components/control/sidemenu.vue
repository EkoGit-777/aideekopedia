<script setup lang="ts">
const sessionStore = useSessionStore()

// onMounted(() => {
//   sessionStore.fetchSessions()
// })
</script>
<template>
  <div class="flex flex-col h-full">
    <div class="p-4 border-b">
      <h2 class="text20 font-bold text-yellow">AideEkopedia</h2>
    </div>
    <nav class="flex-1 overflow-y-auto p-2 space-y-4">
      <NuxtLink to="/" class="block p-2 text-yellow hover:bg-primary-400 rounded-lg">
        New Chat
      </NuxtLink>
      <NuxtLink
        v-for="session in sessionStore.sessions"
        :key="session.id"
        :to="`/chat/${session.id}`"
        class="block p-3 rounded-lg text-yellow hover:bg-primary-400 border"
      >
        Chat {{ session.title }}
      </NuxtLink>
    </nav>
    <div class="p-4 border-t">
      <NuxtLink to="/sign-out" class="block p-2 text-yellow hover:bg-primary-400 rounded-lg">
        Logout
      </NuxtLink>
    </div>
  </div>
</template>