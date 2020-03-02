<template>
    <el-row type="flex" justify="center" style="margin-top: 2rem; margin-bottom: 3rem">
        <el-col :span="24">
            <div class="grid-content">
                <el-card shadow="never">
                    <p>任务统计</p>
                    <el-divider/>

                    <el-row type="flex" :gutter="20">
                        <el-col :span="12">
                            <el-row type="flex" :gutter="20">
                                <el-col :span="12">
                                    <span>扫描状态</span> <br>
                                    <h3>{{ this.curr_task.scan_status }}</h3>
                                </el-col>

                                <el-col :span="12">
                                    <span>在线主机数量</span> <br>
                                    <h3>{{ this.online_host }} / {{ this.all_host }}</h3>
                                </el-col>
                            </el-row>

                            <el-divider/>
                            <el-row type="flex" :gutter="20">
                                <el-col :span="12">
                                    <span>Linux 主机数量</span> <br>
                                    <h3>{{ this.os_type_linux }} / {{ this.all_host }}</h3>
                                </el-col>
                                <el-col :span="12">
                                    <span>Windows 主机数量</span> <br>
                                    <h3>{{ this.os_type_windows }} / {{ this.all_host }}</h3>
                                </el-col>
                            </el-row>
                            <el-row type="flex" :gutter="20">
                                <el-col :span="12">
                                    <span>未知主机数量</span> <br>
                                    <h3>{{ this.os_type_unknown }} / {{ this.all_host }}</h3>
                                </el-col>
                            </el-row>

                            <el-divider/>
                            <el-row type="flex" :gutter="20">
                                <el-col :span="12">
                                    <span>开启端口数</span> <br>
                                    <h3>{{ this.open_port }} / {{ this.all_port }}</h3>
                                </el-col>
                                <el-col :span="12">
                                    <span>关闭端口数</span> <br>
                                    <h3>{{ this.close_port }} / {{ this.all_port }}</h3>
                                </el-col>
                            </el-row>
                            <el-row type="flex" :gutter="20">
                                <el-col :span="12">
                                    <span>过滤端口数</span> <br>
                                    <h3>{{ this.filter_port }} / {{ this.all_port }}</h3>
                                </el-col>
                            </el-row>
                        </el-col>
                        <el-col :span="12">
                            扫描主机操作系统类型占比 <br>
                            <v-chart :options="os_type"/>
                        </el-col>
                    </el-row>

                    <span v-if="curr_task !== null">
                        <el-divider/>
                        <span v-for="host in curr_task.hosts_status" :key="host.ip_addr">
                            <el-row v-if="host.is_online" type="flex" justify="center" style="width: 100%; padding-bottom: 2rem">
                                <el-card shadow="never" style="width: 100%">
                                    <el-row type="flex">
                                        <el-col :span="6">
                                            <span>IP 地址</span> <br>
                                            <h3>{{ host.ip_addr }}</h3>
                                        </el-col>
                                        <el-col :span="6">
                                            <span>主机名</span> <br>
                                            <h3>{{ host.hostname? host.hostname : '无' }}</h3>
                                        </el-col>
                                        <el-col :span="6">
                                            <span>是否在线</span> <br>
                                            <h3>{{ host.is_online? '是' : '否' }}</h3>
                                        </el-col>
                                        <el-col :span="6">
                                            <span>操作系统</span> <br>
                                            <h3>{{ host.os_type }}</h3>
                                        </el-col>
                                    </el-row>
                                    <el-divider/>
                                    <el-row>
                                        <span>开启端口</span>
                                        <pre>{{ render_port_text(host.port_status) }}</pre>
                                    </el-row>
                                </el-card>
                            </el-row>
                        </span>
                    </span>
                </el-card>
            </div>
        </el-col>
    </el-row>
</template>

<script>
    import 'echarts/lib/chart/pie';
    import PORT_NAME_MAP from "@/api/port_map";

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

    export default {
        name: "TaskStatistics",
        props: {
            tasks: Array,
            index: Number
        },
        data() {
            return {
                online_host: 0,
                all_host: 0,
                curr_task: null,
                os_type_windows: 0,
                os_type_linux: 0,
                os_type_unknown: 0,
                all_port: 0,
                open_port: 0,
                close_port: 0,
                filter_port: 0,

                os_type: {
                    title: [],
                    series: [{
                        type: 'pie',
                        data: [],
                        animation: false,
                        label: {
                            position: 'outer',
                            alignTo: 'none',
                            bleedMargin: 5
                        }
                    }]
                }
            }
        },
        methods: {
            update_graph() {
                this.online_host = 0;
                this.all_host = 0;
                this.os_type_windows = 0;
                this.os_type_linux = 0;
                this.os_type_unknown = 0;
                this.curr_task = this.tasks[this.index];

                this.all_port = 0;
                this.open_port = 0;
                this.close_port = 0;
                this.filter_port = 0;

                let os_stat = [
                    {
                        name: 'Linux',
                        value: 0,
                    },
                    {
                        name: 'Windows',
                        value: 0,
                    },
                    {
                        name: 'Unknown',
                        value: 0,
                    },
                ];

                for (let i in this.curr_task.hosts_status) {
                    this.all_host++;
                    let host = this.curr_task.hosts_status[i];
                    if (host.is_online) {
                        this.online_host++;

                        switch (host.os_type) {
                            case "Linux":
                                os_stat[0].value++;
                                this.os_type_linux++;
                                break;
                            case "Windows":
                                os_stat[1].value++;
                                this.os_type_windows++;
                                break;
                            case "Unknown":
                                os_stat[2].value++;
                                this.os_type_unknown++;
                        }

                        for (let i = 0; i < host.port_status.length; i++) {
                            this.all_port++;
                            let port = host.port_status[i];

                            switch (port[1]) {
                                case "OPEN":
                                    this.open_port++;
                                    break;
                                case "CLOSE":
                                    this.close_port++;
                                    break;
                                case "FILTERED":
                                    this.filter_port++;
                                    break;
                            }
                        }
                    }
                }

                this.os_type.series[0].data = os_stat;
            },
            render_port_text(port_status) {
                let ret = "PORT           STATE\tSERVICE\n";
                for (let i = 0; i < port_status.length; i++) {
                    let port = port_status[i];

                    switch (port[1]) {
                        case "OPEN":
                            ret += ((String(port[0]) + '/tcp').padEnd(15, ' ') + 'OPEN\t' + PORT_NAME_MAP[port[0]] + '\n');
                            break;
                        default:
                    }
                }
                return ret;
            }
        },
        watch: {
            tasks: function () {
                this.update_graph()
            },
            index: function () {
                this.update_graph()
            }
        },
    }
</script>

<style scoped>

</style>