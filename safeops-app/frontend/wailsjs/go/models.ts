export namespace main {
	
	export class InstallPaths {
	    install_dir: string;
	    bin_dir: string;
	    data_dir: string;
	    ui_dir: string;
	    backend_dir: string;
	    es_dir: string;
	    kibana_dir: string;
	    version: string;
	
	    static createFrom(source: any = {}) {
	        return new InstallPaths(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.install_dir = source["install_dir"];
	        this.bin_dir = source["bin_dir"];
	        this.data_dir = source["data_dir"];
	        this.ui_dir = source["ui_dir"];
	        this.backend_dir = source["backend_dir"];
	        this.es_dir = source["es_dir"];
	        this.kibana_dir = source["kibana_dir"];
	        this.version = source["version"];
	    }
	}
	export class PrereqStatus {
	    postgresOK: boolean;
	    dbsMissing: string[];
	    elasticOK: boolean;
	    indicesMissing: string[];
	    siemDirOK: boolean;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new PrereqStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.postgresOK = source["postgresOK"];
	        this.dbsMissing = source["dbsMissing"];
	        this.elasticOK = source["elasticOK"];
	        this.indicesMissing = source["indicesMissing"];
	        this.siemDirOK = source["siemDirOK"];
	        this.error = source["error"];
	    }
	}
	export class SIEMState {
	    elasticRunning: boolean;
	    elasticStarting: boolean;
	    kibanaRunning: boolean;
	    kibanaStarting: boolean;
	    siemDir: string;
	    hasScripts: boolean;
	    elasticPid: number;
	    kibanaPid: number;
	    templatesConfigured: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SIEMState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.elasticRunning = source["elasticRunning"];
	        this.elasticStarting = source["elasticStarting"];
	        this.kibanaRunning = source["kibanaRunning"];
	        this.kibanaStarting = source["kibanaStarting"];
	        this.siemDir = source["siemDir"];
	        this.hasScripts = source["hasScripts"];
	        this.elasticPid = source["elasticPid"];
	        this.kibanaPid = source["kibanaPid"];
	        this.templatesConfigured = source["templatesConfigured"];
	    }
	}
	export class ServiceConfig {
	    id: string;
	    name: string;
	    description: string;
	    group: string;
	    exeName: string;
	    subDir: string;
	    args: string[];
	    autoStart: boolean;
	    port: number;
	    portLabel: string;
	    needsAdmin: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ServiceConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.group = source["group"];
	        this.exeName = source["exeName"];
	        this.subDir = source["subDir"];
	        this.args = source["args"];
	        this.autoStart = source["autoStart"];
	        this.port = source["port"];
	        this.portLabel = source["portLabel"];
	        this.needsAdmin = source["needsAdmin"];
	    }
	}
	export class ServiceState {
	    config: ServiceConfig;
	    status: string;
	    pid: number;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ServiceState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.config = this.convertValues(source["config"], ServiceConfig);
	        this.status = source["status"];
	        this.pid = source["pid"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SetupProgress {
	    step: number;
	    total: number;
	    message: string;
	    done: boolean;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new SetupProgress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.step = source["step"];
	        this.total = source["total"];
	        this.message = source["message"];
	        this.done = source["done"];
	        this.error = source["error"];
	    }
	}
	export class SystemStats {
	    cpuPercent: number;
	    memUsedMB: number;
	    memTotalMB: number;
	    memPercent: number;
	    goRoutines: number;
	
	    static createFrom(source: any = {}) {
	        return new SystemStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.cpuPercent = source["cpuPercent"];
	        this.memUsedMB = source["memUsedMB"];
	        this.memTotalMB = source["memTotalMB"];
	        this.memPercent = source["memPercent"];
	        this.goRoutines = source["goRoutines"];
	    }
	}
	export class UserSettings {
	    siem_dir: string;
	    auto_start_firewall: boolean;
	    auto_start_web_ui: boolean;
	    theme: string;
	    last_bin_dir: string;
	
	    static createFrom(source: any = {}) {
	        return new UserSettings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.siem_dir = source["siem_dir"];
	        this.auto_start_firewall = source["auto_start_firewall"];
	        this.auto_start_web_ui = source["auto_start_web_ui"];
	        this.theme = source["theme"];
	        this.last_bin_dir = source["last_bin_dir"];
	    }
	}
	export class WebUIState {
	    backendRunning: boolean;
	    frontendRunning: boolean;
	    backendPid: number;
	    frontendPid: number;
	
	    static createFrom(source: any = {}) {
	        return new WebUIState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.backendRunning = source["backendRunning"];
	        this.frontendRunning = source["frontendRunning"];
	        this.backendPid = source["backendPid"];
	        this.frontendPid = source["frontendPid"];
	    }
	}

}

