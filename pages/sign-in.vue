<script setup lang="ts">
import { reloadNuxtApp } from '#app';

definePageMeta({
  layout: 'auth'
})

onMounted(() => {
  reloadNuxtApp() // Force reload to trigger redirect to Logto
})
</script>
<template><div class="h-dvh max-w-425 text-white">Redirecting to Logto...</div></template>