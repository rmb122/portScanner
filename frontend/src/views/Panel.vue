<template>
    <el-container>
        <el-header style="padding-left: 0px !important; padding-right: 0px !important;">
            <el-menu :default-active="'1'" mode="horizontal">
                <el-menu-item index="1">主机扫描系统</el-menu-item>
                <el-menu-item @click="refresh">刷新</el-menu-item>
                <el-menu-item @click="add_task">添加任务</el-menu-item>
            </el-menu>
        </el-header>
        <el-container>
            <el-aside>
                <el-table
                        ref="singleTable"
                        :data="this.tasks"
                        highlight-current-row
                        :show-header="false"
                        style="margin-top: 3px"
                        @row-click="select_row">
                    <el-table-column
                            type="index"
                            width="50">
                    </el-table-column>
                    <el-table-column
                            property="hosts">
                    </el-table-column>
                    <el-table-column
                            fixed="right"
                            width="50">
                        <template slot-scope="scope">
                            <i class="el-icon-check" v-if="scope.row.scan_status === 'Done'"></i>
                            <i class="el-icon-loading" v-if="scope.row.scan_status === 'Scanning'"></i>
                            <i class="el-icon-time" v-if="scope.row.scan_status === 'Waiting'"></i>
                        </template>
                    </el-table-column>
                </el-table>
            </el-aside>
            <el-main v-loading="loading"  style="border-left-style: solid; border-color: #EBEEF5; border-width: 1px">
                <TaskSetting :tasks="tasks" :index="index" :readonly="true"/>
                <TaskStatistics :tasks="tasks" :index="index"/>
            </el-main>
        </el-container>

        <el-dialog
                title="添加任务"
                :visible.sync="dialog_show"
                width="50%">
            <TaskSetting :tasks="this.new_task_form" :index="0" :readonly="false" :after_submit="close_dialog"/>
        </el-dialog>
    </el-container>
</template>

<script>
    import request from "@/api/request";
    import TaskSetting from "@/components/TaskSetting";
    import TaskStatistics from "@/components/TaskStatistics";

    export default {
        name: "Panel",
        components: {TaskStatistics, TaskSetting},
        data() {
            return {
                tasks: [
                    {
                        hosts: "未选择",
                        ports: "",
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
                        only_ping: false,
                        skip_ping: false,
                        os_rate: 300,
                        port_rate: 300,
                        ping_rate: 300,
                        os_timeout: 3,
                        ping_timeout: 3,
                        port_timeout: 3,
                        output: "",
                        start_time: 0
                    }
                ],
                index: 0,
                loading: false,
                dialog_show: false,
                new_task_form: null
            }
        },
        async mounted() {
            await this.refresh();
        },
        methods: {
            select_row(row) {
                this.index = row.index;
            },
            async refresh() {
                this.loading = true;
                let tasks = (await request.get("/list_task")).data.payload;
                for (let i = 0; i < tasks.length; i++) {
                    tasks[i].index = i;
                }
                this.tasks = tasks;
                this.loading = false;
            },
            async add_task() {
                this.new_task_form = [{
                    hosts: "",
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
                }];

                this.dialog_show = true;
            },
            close_dialog() {
                this.dialog_show = false;
                this.refresh();
            }
        }
    }
</script>

<style scoped>

</style>