<script setup lang="ts">
import { ref } from 'vue'

const inputRef = ref<HTMLInputElement>()
const inputText = defineModel<string | null>({default: null})
const focus = () => {
  inputRef.value?.focus()
}
defineExpose({ focus })
</script>

<template>
  <input ref="inputRef" v-model="inputText" class="focus:outline-none" type="text" />
</template>
