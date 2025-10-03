<script setup lang="ts">
import { ref } from 'vue'

const sessions = ref<SessionType[]>([])
const isOpen = ref(false)

const loadSessions = async () => {
  sessions.value = await $fetch('/api/sessions')
}

onMounted(() => {
  loadSessions()
  // const user = useLogtoUser();
  // const client = useLogtoClient();
  // console.log(user);
  // console.log(client);
})
</script>
<template>
  <div class="flex h-screen">
    <!-- Sidebar (chat list) -->
    <aside class="hidden md:block w-180 border-r bg-primary">
      <ControlSidemenu :sessions="sessions" />
    </aside>

    <!-- Mobile sidebar toggle -->
    <div class="md:hidden absolute top-4 left-4 z-50">
      <button
        @click="isOpen = !isOpen"
        class="p-2 bg-blue-600 text-white rounded-lg"
      >
        ☰
      </button>
    </div>

    <!-- Mobile sidebar drawer -->
    <transition name="slide">
      <aside
        v-if="isOpen"
        class="fixed inset-y-0 left-0 w-64 bg-white border-r z-40 flex flex-col"
      >
        <div class="p-4 border-b flex justify-between items-center">
          <h2 class="text-lg font-bold">Chats</h2>
          <button @click="isOpen = false">✕</button>
        </div>
        <nav class="flex-1 overflow-y-auto p-2 space-y-2">
          <NuxtLink
            v-for="i in 8"
            :key="i"
            :to="`/chat/${i}`"
            class="block p-3 rounded-lg hover:bg-gray-100 border"
            @click="isOpen = false"
          >
            Chat {{ i }}
          </NuxtLink>
        </nav>
        <div class="p-4 border-t">
          <NuxtLink
            to="/sign-out"
            class="block p-2 text-gray-600 hover:bg-gray-100 rounded-lg"
            @click="isOpen = false"
          >
            Logout
          </NuxtLink>
        </div>
      </aside>
    </transition>

    <!-- Main content -->
    <main class="flex-1 flex flex-col bg-primary">
      <NuxtLoadingIndicator />
      <NuxtPage />
    </main>
  </div>
</template>

<style>
.slide-enter-active,
.slide-leave-active {
  transition: transform 0.3s ease;
}
.slide-enter-from,
.slide-leave-to {
  transform: translateX(-100%);
}
</style>
