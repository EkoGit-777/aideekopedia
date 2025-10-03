<script setup lang="ts">
definePageMeta({
  layout: 'default'
})
</script>

<template>
  <div class="p-4 space-y-3">
    <h1 class="text-xl font-bold">Chats</h1>
    <div class="space-y-2">
      <NuxtLink
        v-for="i in 5"
        :key="i"
        :to="`/chat/${i}`"
        class="block p-3 border rounded-lg hover:bg-gray-100"
      >
        <p class="font-semibold">Chat {{ i }}</p>
        <p class="text-sm text-gray-500 truncate">Last message preview...</p>
      </NuxtLink>
    </div>
  </div>
</template>
