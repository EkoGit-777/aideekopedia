<script setup lang="ts">
defineProps<{
  sessions?: SessionType[]
}>()
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
        v-for="i in 8"
        :key="i"
        :to="`/chat/${i}`"
        class="block p-3 rounded-lg text-yellow hover:bg-primary-400 border"
      >
        Chat {{ i }}
      </NuxtLink>
    </nav>
    <div class="p-4 border-t">
      <NuxtLink to="/sign-out" class="block p-2 text-yellow hover:bg-primary-400 rounded-lg">
        Logout
      </NuxtLink>
    </div>
  </div>
</template>