<script setup lang="ts">
import { ref } from 'vue'

const sessions = ref<SessionType[]>([])
const route = useRoute()
const isOpen = ref(false)

const loadSessions = async () => {
  sessions.value = await $fetch('/api/sessions')
}

watch(route, () => {
  isOpen.value = false
})

onMounted(() => {
  loadSessions()
  // const user = useLogtoUser();
  // const client = useLogtoClient();
  // console.log(user);
  // console.log(client);
})
</script>
<template>
  <div class="flex h-screen divide-x divide-yellow">
    <!-- Sidebar (chat list) -->
    <aside class="hidden md:block w-180 bg-primary">
      <ControlSidemenu/>
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
        class="fixed inset-y-0 left-0 w-full bg-primary z-40"
      >
        <div class="py-6 pr-4 pl-32 border-b flex justify-between items-center">
          <div class="text20 text-yellow font-bold">Chats</div>
          <button @click="isOpen = false" class="text-yellow bg-transparent">✕</button>
        </div>
        <ControlSidemenu/>
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
