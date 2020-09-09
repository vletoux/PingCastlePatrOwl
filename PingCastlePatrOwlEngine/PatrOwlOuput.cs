using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Reflection;
using System.Text;

namespace PingCastlePatrOwlEngine
{
    public class PatrOwlOuput
    {
        public PatrOwlOuput(string page, PatrOwlOuputStatus status, string text = null)
        {
            this.page = page;
            this.status = status;
            this.text = text;
        }

        public string page { get; set; }

        [JsonConverter(typeof(StringEnumConverter))] 
        public PatrOwlOuputStatus status { get; set; }

        public string text { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public EngineConfig engine_config { get; set; }


        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PatrOwlScanner scanner { get; set; }
        // other data: "scans":{"98":{"nb_findings":0,"options":{"detect_service_version":1,"script":"libs/vulners.nse","show_open_ports":1},"status":"STARTED"}} when asked in status

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public List<PatrOwlFinding> issues { get; set; }
    }
    public class EngineConfig
    {
        [JsonConverter(typeof(StringEnumConverter))] 
        public PatrOwlOuputStatus status { get; set; } 
        public string version { get; set; }
        public string description { get; set; }
    }

    public class PatrOwlScanner
    {
        public PatrOwlScanner()
        {
            options = new PatrOwlScannerOptions();
            allowed_asset_types = new List<string>() { "ip", "domain", "fqdn" };
            description = "Active Directory Scanner";
            name = "PingCastle";
            path = ConfigurationManager.AppSettings["PingCastle"];
            status = PatrOwlOuputStatus.READY;
            version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
#if DEBUG
            version += " Beta";
#endif
        }
        public List<string> allowed_asset_types { get; set; }
        public string description { get; set; }
        public string name { get; set; }
        public string path { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public PatrOwlOuputStatus status { get; set; }
        public string version { get; set; }

        public PatrOwlScannerOptions options { get; set; }

    }

    public class PatrOwlScannerOptions
    {
        public PatrOwlScannerOptions()
        {
            Login = new PatrOwlScannerOptionsSettings() { type = "optional", value = "--user" };
            Password = new PatrOwlScannerOptionsSettings() { type = "optional", value = "--password" };
            Port = new PatrOwlScannerOptionsSettings() { type = "optional", value = "--port" };
            Protocol = new PatrOwlScannerOptionsSettings() { type = "optional", value = "--protocol" };
        }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PatrOwlScannerOptionsSettings Login { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PatrOwlScannerOptionsSettings Password { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PatrOwlScannerOptionsSettings Port { get; set; }
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public PatrOwlScannerOptionsSettings Protocol { get; set; }
        
    }

    public class PatrOwlScannerOptionsSettings
    {
        public string type { get; set; }
        public string value { get; set; }
    }
    public enum PatrOwlOuputStatus
    {
        ERROR,
        BUSY,
        READY,
        STARTED,
        SCANNING,
        FINISHED,
        accepted,
    }

}
