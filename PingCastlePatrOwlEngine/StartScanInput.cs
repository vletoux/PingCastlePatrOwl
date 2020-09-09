using System;
using System.Collections.Generic;

namespace PingCastlePatrOwlEngine
{
    public class StartScanInput
    {
        public List<StartScanInputAsset> assets { get; set; }
        public StartScanInputOption options { get; set; }
        public int engine_id { get; set; }
        public int scan_id { get; set; }
    }

    public class StartScanInputAsset
    {
        public int id { get; set; }
        public string value { get; set; }
        public string criticity { get; set; }
        public string datatype { get; set; }

    }
    public class StartScanInputOption
    {
        public string Level { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Port { get; set; }
        public string Protocol { get; set; }
    }
}