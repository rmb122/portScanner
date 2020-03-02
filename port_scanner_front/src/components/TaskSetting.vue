<template>
    <el-row type="flex" justify="center" style="margin-top: 0rem">
        <el-col :span="24">
            <div class="grid-content">
                <el-card shadow="never">
                    <p v-if="readonly">任务设置</p>
                    <el-divider v-if="readonly"/>
                    <el-form>
                        <el-row type="flex" justify="center" :gutter="20">
                            <el-col :span="12">
                                <el-form-item label="主机地址">
                                    <el-input type="text" placeholder="192.168.10.1-254" v-model="tasks[index].hosts" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="12">
                                <el-form-item label="扫描端口">
                                    <el-input type="text" placeholder="1-10,11-20 留空则扫描最常使用的 1000 个端口" v-model="tasks[index].ports" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-row type="flex" justify="center" :gutter="20">
                            <el-col :span="12">
                                <el-form-item label="只 ping 主机">
                                    <el-switch v-model="tasks[index].only_ping" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="12">
                                <el-form-item label="跳过 ping 扫描">
                                    <el-switch v-model="tasks[index].skip_ping" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-row type="flex" justify="center" :gutter="20">
                            <el-col :span="8">
                                <el-form-item label="端口扫描速度">
                                    <br>
                                    <el-input-number v-model="tasks[index].port_rate" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="系统类型扫描速度">
                                    <br>
                                    <el-input-number v-model="tasks[index].os_rate" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="ping 扫描速度">
                                    <br>
                                    <el-input-number v-model="tasks[index].ping_rate" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-row type="flex" justify="center" :gutter="20">
                            <el-col :span="8">
                                <el-form-item label="扫描等待时间">
                                    <br>
                                    <el-input-number v-model="tasks[index].port_timeout" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="系统扫描等待时间">
                                    <br>
                                    <el-input-number v-model="tasks[index].os_timeout" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                            <el-col :span="8">
                                <el-form-item label="ping 扫描等待时间">
                                    <br>
                                    <el-input-number v-model="tasks[index].ping_timeout" :disabled="readonly"/>
                                </el-form-item>
                            </el-col>
                        </el-row>

                        <el-form-item>
                            <el-form-item label="扫描开始时间">
                                <el-date-picker
                                        v-model="tasks[index].start_time"
                                        type="datetime"
                                        value-format="timestamp"
                                        placeholder="选择日期"
                                        :disabled="readonly">
                                </el-date-picker>
                            </el-form-item>
                        </el-form-item>

                        <el-form-item v-if="readonly">
                            <el-input type="textarea" :readonly="true" v-model="tasks[index].output" :rows="20">
                            </el-input>
                        </el-form-item>

                        <el-form-item v-if="!readonly">
                            <el-button @click.prevent="submit" type="primary">提交</el-button>
                        </el-form-item>
                    </el-form>
                </el-card>
            </div>
        </el-col>
    </el-row>
</template>

<script>
    /*
        hosts: "未选择",
        ports: "",
        only_ping: false,
        skip_ping: false,
        os_rate: 300,
        port_rate: 300,
        ping_rate: 300,
        os_timeout: 3,
        ping_timeout: 3,
        port_timeout: 3,
        output: "",
        start_time: 0,
        hosts_status: {
        "127.0.0.1": {
            hostname: null,
            ip_addr: "127.0.0.1",
            is_online: true,
            os_type: "Unknown",
            port_status: [
                [1, 'CLOSE']
            ]
        }
        },
     */

    import request from "@/api/request";

    export default {
        name: "TaskSetting",
        props: {
            tasks: Array,
            readonly: Boolean,
            index: Number,
            after_submit: Function
        },
        methods: {
            async submit() {
                let task_form = this.tasks[this.index];

                if (task_form.hosts.trim() !== "") {
                    await request.post("/add_task", task_form);
                    this.$message.success("创建成功");
                    this.after_submit();
                } else {
                    this.$message.error("请输入想要扫描的主机!");
                }
            }
        }
    }
</script>

<style scoped>

</style>