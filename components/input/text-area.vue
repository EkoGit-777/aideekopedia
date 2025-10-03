<script setup lang="ts">
  defineProps<{
    placeholder?: string
  }>()
  const emit = defineEmits<{
    (e: 'enter'): void
  }>()
  const textArea = defineModel<string | null>({default: null})
  const handleKeyUp = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      emit('enter')
    }
  }
</script>
<template>
  <div class="relative box-border max-h-256 min-h-36 w-full flex overflow-hidden">
    <div class="w-full whitespace-pre-line break-words text-justify">
      {{ textArea }}
    </div>
    <textarea
      v-model="textArea"
      name="inputTextArea"
      class="absolute box-border bottom-0 top-0 w-full rounded-12 resize-none overflow-y-auto px-8 py-4 focus:outline-none"
      rows="2"
      :placeholder="placeholder"
      @keyup="handleKeyUp"
    ></textarea>
  </div>
</template>
