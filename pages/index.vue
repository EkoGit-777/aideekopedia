<script setup lang="ts">
import { useSessionStore } from '~/stores/sessions'

const query = ref<string>('')
const sessionStore = useSessionStore()
const router = useRouter()
const startChat = async () => {
  if (!query.value.trim()) return

  // Create session
  await sessionStore.setSessions({
    userId: 'current-user-id', // replace with actual logged-in userId
    title: query.value,        // use first query as session title
  })

  // (optional) redirect to chat page for this session
  // const newSession = sessionStore.sessions.at(-1)
  // navigateTo(`/chat/${newSession.id}`)

  console.log('Session started with title:', query.value)

  // Get the last session that was just added
  const newSession = sessionStore.sessions.at(-1)

  if (newSession) {
    // Redirect to chat page
    router.push({
      path: `/${newSession.id}`,
      query: { first: query.value },
    })
  }

  // clear input
  query.value = ''
}
</script>
<template>
  <div class="relative box-border flex-col flex w-full justify-center px-24 md:px-128 h-full space-y-12 items-center">
    <div class="space-y-8 flex flex-col items-center justify-center h-full md:h-fit">
      <img
        src="/logo.png"
        alt="logo"
        class="w-80 md:w-88 lg:w-104 xl:w-128"
      />
      <div class="text20 text-yellow">What can I help you today?</div>
    </div>
    <div class="py-24 w-full">
      <input-text-area
        class="w-full bottom-24 px-8 py-4 text12 rounded-12"
        placeholder="Ask me anything"
        v-model="query"
        @enter="startChat"
      ></input-text-area>
    </div>
  </div>
</template>