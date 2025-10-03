<script setup lang="ts">
const query = ref<string>('')
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
        @enter="console.log(query)"
      ></input-text-area>
    </div>
  </div>
</template>