package collectors

import (
	"strings"
)

// MACVendorDB provides MAC address vendor lookup with device type classification
type MACVendorDB struct {
	ouiMap map[string]string
}

// NewMACVendorDB creates a new MAC vendor database
func NewMACVendorDB() *MACVendorDB {
	return &MACVendorDB{
		ouiMap: getExtendedOUIDatabase(),
	}
}

// Lookup returns the vendor for a MAC address
func (m *MACVendorDB) Lookup(mac string) string {
	mac = strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	mac = strings.ReplaceAll(mac, "-", "")

	if len(mac) < 6 {
		return "Unknown"
	}

	// Try 6-char OUI lookup
	oui := mac[:6]
	if vendor, ok := m.ouiMap[oui]; ok {
		return vendor
	}

	// Try 8-char lookup (MA-M and MA-S)
	if len(mac) >= 8 {
		oui8 := mac[:8]
		if vendor, ok := m.ouiMap[oui8]; ok {
			return vendor
		}
	}

	return "Unknown"
}

// GetDeviceType returns device type and category based on vendor
func (m *MACVendorDB) GetDeviceType(vendor string) (deviceType, category string) {
	vendorL := strings.ToLower(vendor)

	// Mobile devices
	mobileVendors := []string{
		"apple", "samsung", "huawei", "xiaomi", "oneplus", "oppo", "vivo",
		"realme", "motorola", "lg electronics", "sony mobile", "google",
		"nokia", "htc", "zte", "meizu", "honor", "poco", "nothing",
	}
	for _, v := range mobileVendors {
		if strings.Contains(vendorL, v) {
			return "mobile", "endpoint"
		}
	}

	// Laptops/PCs
	laptopVendors := []string{
		"dell", "hewlett", "hp inc", "lenovo", "asus", "acer", "msi",
		"toshiba", "fujitsu", "microsoft", "razer", "alienware",
		"panasonic", "vaio", "gigabyte",
	}
	for _, v := range laptopVendors {
		if strings.Contains(vendorL, v) {
			return "laptop", "endpoint"
		}
	}

	// Network infrastructure
	networkVendors := []string{
		"cisco", "juniper", "arista", "netgear", "tp-link", "d-link",
		"ubiquiti", "mikrotik", "fortinet", "palo alto", "sonicwall",
		"aruba", "ruckus", "meraki", "zyxel", "linksys", "belkin",
		"huawei network", "h3c", "brocade", "extreme",
	}
	for _, v := range networkVendors {
		if strings.Contains(vendorL, v) {
			return "router", "network_infrastructure"
		}
	}

	// IoT devices
	iotVendors := []string{
		"amazon", "alexa", "ring", "nest", "philips hue", "sonos",
		"ecobee", "wyze", "tuya", "shelly", "espressif", "raspberry",
		"arduino", "particle", "seeed", "adafruit",
	}
	for _, v := range iotVendors {
		if strings.Contains(vendorL, v) {
			return "iot", "smart_device"
		}
	}

	// Gaming
	gamingVendors := []string{
		"sony interactive", "playstation", "microsoft xbox", "nintendo",
		"valve", "steam",
	}
	for _, v := range gamingVendors {
		if strings.Contains(vendorL, v) {
			return "gaming", "entertainment"
		}
	}

	// TV/Streaming
	tvVendors := []string{
		"roku", "chromecast", "fire tv", "vizio", "tcl", "hisense",
		"lg smart", "samsung tv", "apple tv", "nvidia shield",
	}
	for _, v := range tvVendors {
		if strings.Contains(vendorL, v) {
			return "tv", "entertainment"
		}
	}

	// Servers/VMs
	serverVendors := []string{
		"vmware", "hyper-v", "docker", "xen", "oracle vm", "qemu",
		"supermicro", "ibm", "hpe", "oracle",
	}
	for _, v := range serverVendors {
		if strings.Contains(vendorL, v) {
			return "server", "infrastructure"
		}
	}

	// Intel/Realtek are usually PCs
	if strings.Contains(vendorL, "intel") || strings.Contains(vendorL, "realtek") {
		return "desktop", "endpoint"
	}

	return "unknown", "unknown"
}

// getExtendedOUIDatabase returns an extended OUI database
func getExtendedOUIDatabase() map[string]string {
	return map[string]string{
		// Apple (comprehensive)
		"001CB3": "Apple", "286ABA": "Apple", "ACDE48": "Apple", "F0F61C": "Apple",
		"8866F4": "Apple", "5CF7E6": "Apple", "38C986": "Apple", "B8E856": "Apple",
		"D4619D": "Apple", "F0D1A9": "Apple", "44D884": "Apple", "F8FF61": "Apple",
		"A45E60": "Apple", "9C8BA0": "Apple", "20A2E4": "Apple", "1C9148": "Apple",
		"F0C3B5": "Apple", "9CE33F": "Apple", "78A3E4": "Apple", "BCE5C5": "Apple",
		"98B8E3": "Apple", "946AE5": "Apple", "4C3275": "Apple", "D0034B": "Apple",
		"84FC FE": "Apple", "E8B2AC": "Apple",

		// Samsung
		"A477B3": "Samsung", "E850B8": "Samsung", "08D4C5": "Samsung", "5C0947": "Samsung",
		"DC71B3": "Samsung", "B4F0AB": "Samsung", "40D3AE": "Samsung", "34DA56": "Samsung",
		"6CB7F4": "Samsung", "2C7E81": "Samsung", "AC5F3E": "Samsung", "F81A67": "Samsung",
		"84D355": "Samsung", "C870EB": "Samsung", "9C2A83": "Samsung", "78D6F0": "Samsung",

		// Google
		"001A11": "Google", "F88FCA": "Google", "3C5A37": "Google", "F4F5E8": "Google",
		"94EB2C": "Google", "54605F": "Google", "B4CE40": "Google", "44077D": "Google",
		"B0E4D5": "Google", "18D6CF": "Google",

		// Huawei
		"00E0FC": "Huawei", "84A134": "Huawei", "D0C637": "Huawei", "F8E81A": "Huawei",
		"48B02D": "Huawei", "60DE44": "Huawei", "34CDBE": "Huawei", "5C8F40": "Huawei",
		"78D752": "Huawei", "34B3FF": "Huawei", "74882A": "Huawei", "CC96A0": "Huawei",

		// Xiaomi
		"34CE00": "Xiaomi", "64B473": "Xiaomi", "F4F524": "Xiaomi", "9C99A0": "Xiaomi",
		"28E31F": "Xiaomi", "50F1F2": "Xiaomi", "7C496C": "Xiaomi", "ACCC8E": "Xiaomi",
		"D4970B": "Xiaomi", "3C2EFF": "Xiaomi", "B8AF67": "Xiaomi",

		// Dell
		"001C23": "Dell", "B8CA3A": "Dell", "D4AE52": "Dell", "F8DB88": "Dell",
		"00219B": "Dell", "9CEBEB": "Dell", "F04DA2": "Dell", "C81F66": "Dell",
		"844FE8": "Dell", "78AC44": "Dell", "3C2C30": "Dell", "74867A": "Dell",

		// HP/Hewlett-Packard
		"009C02": "Hewlett-Packard", "708BCD": "Hewlett-Packard", "D48564": "Hewlett-Packard",
		"80E82C": "Hewlett-Packard", "D8D385": "Hewlett-Packard", "94576B": "Hewlett-Packard",
		"78E3B5": "Hewlett-Packard", "D4C94B": "Hewlett-Packard", "B0A737": "Hewlett-Packard",
		"2C44FD": "Hewlett-Packard", "A0D3C1": "Hewlett-Packard", "68B599": "Hewlett-Packard",

		// Lenovo
		"00216A": "Lenovo", "5CF938": "Lenovo", "28D244": "Lenovo", "E8D0FC": "Lenovo",
		"00064F": "Lenovo", "ECAA25": "Lenovo", "586D8F": "Lenovo", "50657F": "Lenovo",
		"54E1AD": "Lenovo", "ECFA03": "Lenovo", "98FA9B": "Lenovo", "7C7A91": "Lenovo",

		// Asus
		"107B44": "ASUS", "1CBF2E": "ASUS", "D850E6": "ASUS", "60A44C": "ASUS",
		"AC22F9": "ASUS", "40167E": "ASUS", "E0CB4E": "ASUS", "00E018": "ASUS",
		"24EE04": "ASUS", "B06EBF": "ASUS", "A4FC77": "ASUS", "54046B": "ASUS",

		// Microsoft
		"00155D": "Microsoft", "0050F2": "Microsoft", "64006A": "Microsoft", "28187A": "Microsoft",
		"9C8356": "Microsoft", "F42B48": "Microsoft", "BCCCA0": "Microsoft", "CC0561": "Microsoft",
		"7C1E52": "Microsoft", "001DD8": "Microsoft", "7CED8D": "Microsoft",

		// Intel
		"001B77": "Intel", "A45D36": "Intel", "3C4E60": "Intel", "64D4DA": "Intel",
		"D4258B": "Intel", "006042": "Intel", "68F728": "Intel", "CC0300": "Intel",
		"C8D3FF": "Intel", "E8D8D1": "Intel", "7C7A53": "Intel", "48F17F": "Intel",

		// Realtek
		"00E04C": "Realtek", "52540E": "Realtek", "00E04D": "Realtek", "8C09A4": "Realtek",
		"28F366": "Realtek", "A81B5A": "Realtek", "10D07A": "Realtek",

		// TP-Link
		"F4F2A3": "TP-Link", "C006C3": "TP-Link", "0023CD": "TP-Link", "EC172F": "TP-Link",
		"483C0C": "TP-Link", "D85D4C": "TP-Link", "54C80F": "TP-Link", "F0F336": "TP-Link",
		"AC84C6": "TP-Link", "5CE882": "TP-Link",

		// D-Link
		"001B11": "D-Link", "C0A0BB": "D-Link", "1CBE4A": "D-Link", "28107B": "D-Link",
		"842612": "D-Link", "BCFF4D": "D-Link", "6CFF18": "D-Link",

		// Cisco
		"001EE5": "Cisco", "00213B": "Cisco", "002618": "Cisco", "00259C": "Cisco",
		"0026CB": "Cisco", "001F9E": "Cisco", "001DB5": "Cisco", "001C10": "Cisco",
		"000DBC": "Cisco", "001121": "Cisco", "00269E": "Cisco", "0025B4": "Cisco",

		// Netgear
		"001E2A": "Netgear", "00245E": "Netgear", "0026F2": "Netgear", "002781": "Netgear",
		"5C4CA9": "Netgear", "84C2E4": "Netgear", "A42B8C": "Netgear", "C03F0E": "Netgear",

		// Ubiquiti
		"00156D": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti", "B4FBE4": "Ubiquiti",
		"24A43C": "Ubiquiti", "802AA8": "Ubiquiti", "FC EC DA": "Ubiquiti",

		// Amazon
		"F0D2F1": "Amazon", "FCA667": "Amazon", "84D6D0": "Amazon", "74C246": "Amazon",
		"0C47C9": "Amazon", "A0C9A0": "Amazon", "48CB6B": "Amazon", "34D270": "Amazon",

		// Sony
		"001EA9": "Sony", "8C7712": "Sony", "F8461C": "Sony", "7C5F2C": "Sony",
		"AC63BE": "Sony", "0019C5": "Sony", "001793": "Sony",

		// Sony PlayStation
		"F8D0AC": "Sony PlayStation", "78C881": "Sony PlayStation", "C8B2F9": "Sony PlayStation",
		"001315": "Sony PlayStation",

		// LG
		"E8039A": "LG Electronics", "609217": "LG Electronics", "BCAD28": "LG Electronics",
		"9480B6": "LG Electronics", "6CD032": "LG Electronics", "34E6AD": "LG Electronics",

		// OnePlus
		"AC37B4": "OnePlus", "806F74": "OnePlus", "C01213": "OnePlus",

		// Nintendo
		"7CBB8A": "Nintendo", "E00C7F": "Nintendo", "0009BF": "Nintendo", "58BD52": "Nintendo",
		"0025A0": "Nintendo", "0017AB": "Nintendo", "002659": "Nintendo",

		// Roku
		"D45658": "Roku", "C8052C": "Roku", "B8AE6E": "Roku", "8CCFCD": "Roku",
		"ACF02B": "Roku", "CCE1D5": "Roku", "B0A7B9": "Roku",

		// VMware
		"005056": "VMware", "000C29": "VMware", "005059": "VMware",

		// Espressif (ESP8266/ESP32 IoT)
		"5CCF7F": "Espressif", "24B2DE": "Espressif", "A4CF12": "Espressif",
		"8CE748": "Espressif", "BCD0F2": "Espressif", "AC67B2": "Espressif",

		// Raspberry Pi
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",

		// Hyper-V
		"0003FF": "Hyper-V",

		// Acer
		"001C26": "Acer", "18CF5E": "Acer", "D0667B": "Acer", "38D547": "Acer",

		// MSI
		"00D861": "MSI", "BC5FF4": "MSI", "F0A4A0": "MSI",

		// Motorola
		"00037A": "Motorola", "5CBC59": "Motorola", "34BB26": "Motorola",
		"98D6F7": "Motorola", "E8088B": "Motorola",

		// Oppo
		"04D6F4": "Oppo", "640B5D": "Oppo", "3CE7F4": "Oppo", "2C9176": "Oppo",

		// Vivo
		"546C6B": "Vivo", "88D50C": "Vivo", "A0F498": "Vivo",

		// Realme
		"B80B95": "Realme", "F4B7E2": "Realme",

		// ZTE
		"5C96B6": "ZTE", "BC7670": "ZTE", "8CF228": "ZTE",

		// Philips Hue
		"001788": "Philips Hue", "ECBB40": "Philips Hue",

		// Sonos
		"0004ED": "Sonos", "782849": "Sonos", "7CE87B": "Sonos",

		// Ring (Doorbell)
		"2C4D54": "Ring", "CC3A61": "Ring",

		// Nest
		"1893D7": "Nest", "64167F": "Nest", "D8EB46": "Nest",

		// Chromecast
		"F4F5D8": "Chromecast",

		// Fire TV
		"24F4BB": "Fire TV",
	}
}
