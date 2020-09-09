using Newtonsoft.Json;
using PingCastle;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Remoting.Channels;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;

namespace PingCastle
{
    public class BotInputOutput
    {
        public List<BotData> Data { get; set; }

    }
    public class BotData
    {
        public BotData()
        {

        }
        public BotData(string Key, string Value) : this()
        {
            this.Key = Key;
            this.Value = Value;
        }
        public string Key { get; set; }
        public string Value { get; set; }
    }
}

namespace PingCastlePatrOwlEngine
{
    public class ScanJob
    {

        Process Bot = null;
        public PatrOwlOuputStatus Status { get; private set; }

        public string Error { get; private set; }
        StartScanInput ScanSetting;

        List<BotInputOutput> results = new List<BotInputOutput>();
        List<PatrOwlFinding> errors;

        NamedPipeServerStream pipe;

        bool stop = false;

        public void Start(StartScanInput input)
        {
            ScanSetting = input;
            try
            {
                lock (this)
                {
                    StartBot();
                }
            }
            catch(Exception ex)
            {
                Error = ex.Message;
                Status = PatrOwlOuputStatus.ERROR;
                return;
            }
            Status = PatrOwlOuputStatus.STARTED;
            var t = new Thread(AnalyzeData);
            t.Start();

            // assert the thread as joined the program
            for(int i = 0; i < 50; i++)
            {
                lock (this)
                {
                    Thread.Sleep(100);
                    if (Status != PatrOwlOuputStatus.STARTED)
                    {
                        Console.WriteLine("scan started");
                        return;
                    }
                }
            }
            // if not, kill the thread
            try
            {
                Console.WriteLine("scan aborted");
                t.Abort();
            }
            catch(Exception)
            {

            }
            Status = PatrOwlOuputStatus.ERROR;
            Error = "Scan program didn't join the pipe";
        }

        // si scan fail pour 1 machine (sur plusieurs) => ajouter findings pour cette machine
        // scan toujours successful, mais ajouter en findings les raisons des echecs
        public void AnalyzeData()
        {   
            pipe.WaitForConnection();
            lock(this)
            {
                Status = PatrOwlOuputStatus.SCANNING;
            }

            foreach (var t in ScanSetting.assets)
            {
                bool hasError = false;
                if (stop)
                    continue;
                try
                {
                    var output = RunHealthCheck(t);
                    string status = GetItem(output, "Status");
                    switch (status)
                    {
                        case "OK":
                            results.Add(output);
                            continue;
                        case "Error":
                            Error = GetItem(output, "Error");
                            hasError = true;
                            break;
                        default:
                            Error = "Invalid return code " + status;
                            hasError = true;
                            break;
                    }
                }
                catch(Exception ex)
                {
                    hasError = true;
                    Error = "Exception when running job: " + ex.Message;
                }
                if (hasError)
                {
                    var o = new PatrOwlFinding();
                    o.issue_id = 0;
                    o.timestamp = DateTime.Now;
                    o.target = new PatrOwlFindingTarget();
                    o.target.addr = new List<string>() { t.value };
                    o.type = "pingcastle";
                    o.confidence = PatrOwlFindingConfidenceEnum.certain;
                    o.PingCastleTitle = "An error occured while running the scan";
                    o.PingCastleTechnicalExplanation = "The error is:\r\n" + Error;
                    o.solution = "We recommand to check the settings defined in the scan and if the scanner can reach the domain it has been asked to scan";
                    o.title = "An error occured while running the scan";
                    o.severity = PatrOwlFindingSeverityEnum.critical;
                    if (errors == null)
                        errors = new List<PatrOwlFinding>();
                    errors.Add(o);
                }
            }
            Status = PatrOwlOuputStatus.FINISHED;
            try
            {
                SendAndReceiveCommand(GenerateNewCommand("shutdown"));
            }
            catch(Exception)
            {

            }
            Stop();
        }

        public void Stop()
        {
            stop = true;

            Thread.Sleep(100);
            lock (this)
            {
                if (Bot == null)
                    return;
                if (!Bot.HasExited)
                {
                    Bot.Kill();
                }
                pipe.Close();
                pipe = null;
                Bot = null;
            }
        }

        public List<PatrOwlFinding> GetFindings()
        {
            var output = new List<PatrOwlFinding>();
            var re = new Regex("^(?<control>[a-zA-Z]+)_(?<index>\\d+)$");
            int k = 1;
            if (errors != null)
            {
                foreach (var error in errors)
                    output.Add(error);
            }
            if (results != null)
            {
                foreach (var report in results)
                {
                    var o = new Dictionary<int, PatrOwlFinding>();
                    foreach (var item in report.Data)
                    {
                        var m = re.Match(item.Key);
                        if (m.Success)
                        {
                            int id = int.Parse(m.Groups["index"].Value);

                            if (!o.ContainsKey(id))
                            {
                                o[id] = new PatrOwlFinding();
                                o[id].issue_id = id;
                                o[id].timestamp = DateTime.Now;
                                o[id].target = new PatrOwlFindingTarget();
                                o[id].target.addr = new List<string>() { GetItem(report, "Target") };
                                o[id].type = "pingcastle";
                                o[id].confidence = PatrOwlFindingConfidenceEnum.certain;
                            }
                            PatrOwlFinding p = o[id];
                            string control = m.Groups["control"].Value;
                            string value = item.Value;
                            switch (control)
                            {
                                case "Rationale":
                                    p.title = value;
                                    p.raw = value;
                                    break;
                                case "Title":
                                    p.PingCastleTitle = value;
                                    break;
                                case "TechnicalExplanation":
                                    p.PingCastleTechnicalExplanation = value;
                                    break;
                                case "Solution":
                                    p.solution = value;
                                    break;
                                case "Detail":
                                    if (p.PingCastleDetail == null)
                                        p.PingCastleDetail = new List<string>();
                                    p.PingCastleDetail.Add(value);
                                    break;
                                case "Points":
                                    {
                                        int point = 0;
                                        int.TryParse(value, out point);
                                        p.severity = GetSeverity(point);
                                    }
                                    break;
                                case "Documentation":
                                    {
                                        o[id].metadata = new PatrOwlFindingMetadata();
                                        o[id].metadata.links = new List<string>();
                                        var links = o[id].metadata.links;
                                        var relink = new Regex("<a\\s+(?:[^>]*?\\s+)?href=([\"'])(?<url>(.*?))\\1");
                                        foreach (Match link in relink.Matches(value))
                                        {
                                            var l = link.Groups["url"].Value;
                                            if (!links.Contains(l))
                                                links.Add(l);
                                        }
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                    foreach (var i in o.Values)
                    {
                        i.issue_id = k++;
                        output.Add(i);
                    }
                }
            }
            return output;
        }

        public void getReports(Stream output)
        {
            // no use of output stream because the output stream do not support to change position used by zipstream.write
            using (MemoryStream ms = new MemoryStream())
            {
                using (ZipArchive file = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    foreach (var report in results)
                    {
                        var r = GetItem(report, "Report");
                        if (string.IsNullOrEmpty(r))
                            continue;

                        XmlDocument doc = new XmlDocument();
                        doc.LoadXml(r);

                        string json = JsonConvert.SerializeXmlNode(doc);

                        var filename = GetItem(report, "Target") + ".json";
                        var entry = file.CreateEntry(filename);
                        using (var zipStream = entry.Open())
                        {
                            var data = Encoding.UTF8.GetBytes(json);
                            zipStream.Write(data, 0, data.Length);
                        }
                    }
                }
                ms.Position = 0;
                ms.CopyTo(output);
            }
        }

        private PatrOwlFindingSeverityEnum GetSeverity(int points)
        {
            if (points == 0)
                return PatrOwlFindingSeverityEnum.info;
            if (points <= 10)
                return PatrOwlFindingSeverityEnum.low;
            if (points <= 30)
                return PatrOwlFindingSeverityEnum.medium;
            if (points <= 50)
                return PatrOwlFindingSeverityEnum.high;
            return PatrOwlFindingSeverityEnum.critical;
        }

        void StartBot()
        {
            var pipeName = Guid.NewGuid().ToString();
            pipe = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte);

            Bot = new Process();

            Bot.StartInfo.FileName = ConfigurationManager.AppSettings["PingCastle"];
            Bot.StartInfo.Arguments = "--bot " + pipeName;
            Bot.StartInfo.UseShellExecute = false;

            Bot.Start();
        }

        BotInputOutput SendAndReceiveCommand(BotInputOutput input)
        {
            XmlSerializer xs = new XmlSerializer(typeof(BotInputOutput));
            lock (this)
            {
                try
                {
                    if (Bot == null || !Bot.Responding)
                    {
                        throw new ApplicationException("Job stopped");
                    }

                    using (var ms = new MemoryStream())
                    using (XmlWriter writer = XmlWriter.Create(ms))
                    {
                        xs.Serialize(writer, input);
                        ms.Position = 0;
                        var buffer = ms.GetBuffer();
                        var t = BitConverter.GetBytes((int)ms.Length);
                        pipe.Write(t, 0, 4);
                        pipe.Write(buffer, 0, (int)ms.Length);
                    }
                    Console.WriteLine("Master: message sent");
                }
                catch (Exception ex)
                {
                    throw new ApplicationException("Exception when sending " + ex.Message);
                }
            }
            try
            {
                var buffer = new byte[4];
                int read = pipe.Read(buffer, 0, 4);
                if (read < 4)
                    throw new ApplicationException("Pipe shutdown");
                int count = BitConverter.ToInt32(buffer, 0);
                var data = new byte[count];
                read = 0;
                while (read < count)
                {
                    int r = pipe.Read(data, read, count - read);
                    if (r == 0)
                        throw new ApplicationException("Pipe shutdown");
                    read += r;
                }
                Console.WriteLine("Master: message received");
                //
                using (var ms = new MemoryStream(data))
                {
                    
                    var output = (BotInputOutput)xs.Deserialize(ms);
                    return output;
                }
            }
            catch(Exception ex)
            {
                throw new ApplicationException("Exception when receiving " + ex.Message);
            }
        }

        BotInputOutput RunHealthCheck(StartScanInputAsset Asset)
        {
            BotInputOutput input = GenerateNewCommand("healthcheck");
            var Login = ScanSetting.options?.Login;
            var Password = ScanSetting.options?.Password;
            var Port = ScanSetting.options?.Port;
            var Protocol = ScanSetting.options?.Protocol;
            if (!string.IsNullOrEmpty(Login))
            {
                AddData(input, "Login", Login);
            }
            if (!string.IsNullOrEmpty(Password))
            {
                AddData(input, "Password", Password);
            }
            if (!string.IsNullOrEmpty(Port))
            {
                AddData(input, "Port", Port);
            }
            if (!string.IsNullOrEmpty(Protocol))
            {
                AddData(input, "Protocol", Protocol);
            }
            AddData(input, "Server", Asset.value);
            return SendAndReceiveCommand(input);


        }

        BotInputOutput GetHTMLReport(string xmlReport)
        {
            BotInputOutput input = GenerateNewCommand("tohtml");
            AddData(input, "Report", xmlReport);
            return SendAndReceiveCommand(input);
        }

        private static BotInputOutput GenerateNewCommand(string command)
        {
            var input = new BotInputOutput();
            input.Data = new List<BotData>();
            AddData(input, "Command", command);
            return input;
        }

        private static void AddData(BotInputOutput o, string key, string value)
        {
            o.Data.Add(new BotData(key, value));
        }

        static string GetItem(BotInputOutput input, string key)
        {
            foreach (var k in input.Data)
            {
                if (k.Key == key)
                    return k.Value;
            }
            return null;
        }
    }
}
