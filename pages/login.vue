<script setup lang="ts">
definePageMeta({
  layout: 'auth'
})

const handleLogin = () => {
  const router = useRouter()
  router.push('/sign-in')
}
</script>
<template>
  <div class="h-dvh w-425 flex flex-col justify-center items-center px-64 space-y-16">
    <img
      src="/logo.png"
      alt="logo"
      class="w-96 md:w-108 lg:w-120 xl:w-132"
    />
    <div class="text20 text-yellow">AideEkopedia</div>
    <form class="w-full space-y-8 bg-white p-16 rounded-8">
      <div class="text-24 font-bold text-center mb-8">Login</div>
      <control-button-primary class="w-full p-4" @click="handleLogin">Login with Logto</control-button-primary>
    </form>
  </div>
</template>