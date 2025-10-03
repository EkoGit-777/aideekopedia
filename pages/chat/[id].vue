<script setup lang="ts">
import { Chat } from "@ai-sdk/vue";
import { ref } from "vue";

const query = ref("");
const chat = new Chat({});

const handleSubmit = () => {
    chat.sendMessage({ text: query.value });
    query.value = "";
};
</script>

<template>
  <div class="relative box-border flex-col flex w-full justify-center px-24 md:px-128 h-full space-y-12 items-center">
    <div class="space-y-8 flex-1 flex-col w-full py-24 overflow-y-auto">
      <div
        v-for="(m, index) in chat.messages" :key="m.id ? m.id : index"
        class="w-full text-white flex"
        :class="{'justify-end':m.role === 'user'}">
          <div
              v-for="(part, index) in m.parts"
              :key="`${m.id}-${part.type}-${index}`"
              :class="{'bg-yellow text-black rounded-8 p-8':m.role === 'user'}"
          >
              <div v-if="part.type === 'text'">{{ part.text }}</div>
          </div>
      </div>
    </div>
    <div class="py-24 w-full">
      <input-text-area
        class="w-full bottom-24 px-8 py-4 text12 rounded-12"
        placeholder="Ask me anything"
        v-model="query"
        @enter="handleSubmit"
      ></input-text-area>
    </div>
  </div>
</template>