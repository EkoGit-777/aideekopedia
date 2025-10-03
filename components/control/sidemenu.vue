<script setup lang="ts">
defineProps<{
  sessions?: SessionType[]
}>()
</script>
<template>
  <div>
    <div class="p-4 border-b">
      <h2 class="text20 font-bold">AideEkopedia</h2>
    </div>
    <nav class="flex-1 overflow-y-auto p-2 space-y-2">
      <NuxtLink
        v-for="i in 8"
        :key="i"
        :to="`/chat/${i}`"
        class="block p-3 rounded-lg hover:bg-gray-100 border"
      >
        Chat {{ i }}
      </NuxtLink>
    </nav>
    <div class="p-4 border-t">
      <NuxtLink to="/sign-out" class="block p-2 text-gray-600 hover:bg-gray-100 rounded-lg">
        Logout
      </NuxtLink>
    </div>
  </div>
</template>