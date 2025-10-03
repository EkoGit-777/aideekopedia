<script setup lang="ts">
  import { computed, ref } from 'vue'

  defineProps<{
    modelValue: string
    placeholder?: string
    autocomplete?: string
    required?: boolean
    classInput?: string | object
  }>()
  const emit = defineEmits<{
    (e: 'update:modelValue', data: string): void
  }>()
  const isPassword = ref(true)
  const inputRef = ref<HTMLInputElement>()
  const typePassword = computed(() => (isPassword.value ? 'password' : 'text'))

  const focus = () => {
    inputRef.value?.focus()
  }
  defineExpose({ focus })
</script>
<template>
  <div class="relative w-full flex bg-none outline-none">
    <input
      ref="inputRef"
      :value="modelValue"
      :type="typePassword"
      :placeholder="placeholder"
      name="password"
      :required="required"
      :autocomplete="autocomplete ?? 'current-password'"
      class="text10 w-full rounded-4 px-6 py-4 text-gray-950 focus:outline-none"
      :class="classInput"
      @input="
        (event) => emit('update:modelValue', (event.target as HTMLInputElement).value)
      "
    />
    <control-button-component
      class="text12 absolute inset-y-0 right-8 w-20 flex items-center justify-center"
      type="button"
      tabindex="-1"
      @click="isPassword = !isPassword"
    >
      <i
        class="inline-block text-gray"
        :class="isPassword ? 'i-fas-eye-slash' : 'i-fas-eye'"
      ></i>
    </control-button-component>
  </div>
</template>
