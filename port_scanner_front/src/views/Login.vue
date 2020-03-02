<template>
    <el-row type="flex" justify="center" style="transform: translateY(80%)">
        <el-col :span="8">
            <div class="grid-content">
                <el-card>
                    <h2>系统登录</h2>
                    <el-form @keydown.enter.native="submit" v-loading="loading">
                        <el-form-item label="密码">
                            <el-input type="password" placeholder="密码" v-model="form.password"/>
                        </el-form-item>
                        <el-form-item>
                            <el-button @click.prevent="submit" type="primary">提交</el-button>
                        </el-form-item>
                    </el-form>
                </el-card>
            </div>
        </el-col>
    </el-row>
</template>

<script>
    import login from "@/api/login";

    export default {
        name: "Login",
        data() {
            return {
                loading: false,
                form: {
                    password: ""
                }
            }
        },
        methods: {
            async submit() {
                console.log(123)
                let res = await login.login(this.form.password);
                if (res.data.code === 200) {
                    this.$router.push({"path": "/panel"});
                } else {
                    this.$message.error("密码错误");
                }
            }
        }
    }
</script>

<style scoped>

</style>