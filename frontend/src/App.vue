<template>
    <div id="app">
        <router-view v-loading="loading"/>
    </div>
</template>

<script>
  import login from "@/api/login";

  export default {
        name: "App",
        data() {
          return {
            loading: false
          }
        },
        async mounted() {
            this.loading = true;
            let status = await login.status();
            if (status.data.code === 200) {
                this.$router.push({"path": "/panel"});
            } else {
                this.$router.push({"path": "/"});
            }
            this.loading = false;
        }
    }
</script>

<style>

</style>
