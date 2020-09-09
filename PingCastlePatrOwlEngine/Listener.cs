using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PingCastlePatrOwlEngine
{
    public class Listener
    {
        HttpListener listener;
        string bindings = ConfigurationManager.AppSettings["Binding"];


        Dictionary<int, ScanJob> ScanJobs = new Dictionary<int, ScanJob>();

        public void Start()
        {
            if (!bindings.EndsWith("/"))
                bindings = bindings + "/";
            listener = new HttpListener();
            listener.Prefixes.Add(bindings);
            listener.Start();

            ThreadPool.QueueUserWorkItem((o) =>
            {
                Console.WriteLine("Webserver running...");
                try
                {
                    while (listener.IsListening)
                    {
                        ThreadPool.QueueUserWorkItem((c) =>
                        {
                            var ctx = c as HttpListenerContext;
                            try
                            {
                                handleRequest(ctx);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ctx.Request.RawUrl + " - " + ex.Message);
                                Console.WriteLine(ex.StackTrace);
                            } // suppress any exceptions
                            finally
                            {
                                ctx.Response.OutputStream.Close();
                            }
                        }, listener.GetContext());
                    }
                }
                catch { } // suppress any exceptions
            });
        }

        private void handleRequest(HttpListenerContext ctx)
        {
            HttpListenerRequest request = ctx.Request;
            int index = -1;
            var u = new Uri(bindings.Replace("*", "localhost").Replace("+", "localhost"));
            var url = request.RawUrl.Substring(u.AbsolutePath.Length);

            if (string.IsNullOrEmpty(url))
            {
                url = "index";
            }
            var re = new Regex("^(?<page>[a-zA-Z]+)(\\/(?<index>\\d+))?$");
            Match m = re.Match(url);
            if (!m.Success)
            {
                ReturnDefaultOutput(ctx, new PatrOwlOuput("unkown", PatrOwlOuputStatus.ERROR, "No match with url pattern"));
                return;
            }
            string page = m.Groups["page"].Value;
            if (m.Groups["index"].Success)
                index = int.Parse(m.Groups["index"].Value);

            page = page.ToLowerInvariant();

            Console.WriteLine("[" + DateTime.Now + "] Calling page: " + page + " " + (index >= 0 ? index.ToString() : null));

            switch(page)
            {
                case "test":
                    ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                    return;
                case "liveness":
                    ReturnOK(ctx);
                    return;
                case "readiness":
                    ReturnOK(ctx);
                    return;
                case "info":
                    {
                        var o = new PatrOwlOuput(page, PatrOwlOuputStatus.READY);
                        o.engine_config = new EngineConfig()
                        {
                            version = "2.8",
                            description = "PingCastle",
                            status = PatrOwlOuputStatus.READY, // si scan: BUSY si trop de scan
                        };
                        ReturnDefaultOutput(ctx, o);
                        return;
                    }
                case "clean":
                    {
                        if (index >= 0)
                        {
                            if (!ScanJobs.ContainsKey(index))
                            {
                                ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY, "Unknown Scan Id"));
                                return;
                            }
                            var job = ScanJobs[index];
                            if (job.Status != PatrOwlOuputStatus.FINISHED)
                            {
                                ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Scan not finished"));
                                return;
                            }
                            ScanJobs.Remove(index);
                        }
                        else
                        {
                            ScanJobs.Clear();
                        }
                        ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                        return;
                    }
                case "stopscans":
                    {
                        foreach(var scan in ScanJobs.Values)
                        {
                            scan.Stop();
                        }
                        ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                        return;
                    }
                case "stop":
                    {
                        if (!ScanJobs.ContainsKey(index))
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY, "Unknown Scan Id"));
                            return;
                        }
                        var job = ScanJobs[index];
                        job.Stop();
                        ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                        return;
                    }
                case "startscan":
                    {
                        StartScanInput input;
                        JsonSerializer serializer = new JsonSerializer();
                        using (var i = new JsonTextReader(new StreamReader(request.InputStream)))
                        {
                            input = (StartScanInput)serializer.Deserialize(i, typeof(StartScanInput));
                        }
                        if (input.assets == null || input.assets.Count == 0)
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "No assets to scan"));
                            return;
                        }
                        if (ScanJobs.ContainsKey(input.scan_id))
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Scan Id already used"));
                            return;
                        }
                        
                        var job = new ScanJob();
                        ScanJobs.Add(input.scan_id, job);
                        job.Start(input);
                        ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.accepted));
                        return;
                    }
                case "status":
                    {
                        if (index == -1)
                        {
                            var o = new PatrOwlOuput(page, PatrOwlOuputStatus.READY);
                            o.scanner = new PatrOwlScanner();
                            ReturnDefaultOutput(ctx, o);
                            return;
                        }
                        if (!ScanJobs.ContainsKey(index))
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Unknown Scan Id"));
                            return;
                        }
                        var job = ScanJobs[index];
                        ReturnDefaultOutput(ctx, new PatrOwlOuput(page, job.Status));
                        return;
                    }
                case "index":
                    ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                    return;
                case "getfindings":
                    {
                        if (index == -1)
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "No scan Id provided"));
                            return;
                        }
                        if (!ScanJobs.ContainsKey(index))
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Unknown Scan Id"));
                            return;
                        }
                        var job = ScanJobs[index];
                        if (job.Status != PatrOwlOuputStatus.FINISHED)
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Job not finished"));
                            return;
                        }
                        var o = new PatrOwlOuput(page, PatrOwlOuputStatus.FINISHED);
                        o.issues = job.GetFindings();
                        ReturnDefaultOutput(ctx, o);
                        return;
                    }
                case "getreport":
                    {
                        if (index == -1)
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.READY));
                            return;
                        }
                        if (!ScanJobs.ContainsKey(index))
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Unknown Scan Id"));
                            return;
                        }
                        var job = ScanJobs[index];
                        if (job.Status != PatrOwlOuputStatus.FINISHED)
                        {
                            ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR, "Job not finished"));
                            return;
                        }
                        ctx.Response.ContentType = "application/zip";
                        job.getReports(ctx.Response.OutputStream);
                        return;
                    }
                default:
                    ReturnDefaultOutput(ctx, new PatrOwlOuput(page, PatrOwlOuputStatus.ERROR));
                    return;
            }
        }


        void ReturnDefaultOutput(HttpListenerContext ctx, PatrOwlOuput o)
        {
            ctx.Response.ContentType = "application/json";
            using (var sw = new StreamWriter(ctx.Response.OutputStream))
            using (var i = new JsonTextWriter(sw))
            {
                JsonSerializer serializer = new JsonSerializer();
                serializer.NullValueHandling = NullValueHandling.Ignore;
                serializer.Serialize(i, o, typeof(StartScanInput));
            }
            Console.WriteLine(" --> " + o.status.ToString());
        }

        void ReturnOK(HttpListenerContext ctx)
        {
            using (var sw = new StreamWriter(ctx.Response.OutputStream))
            {
                sw.WriteLine("OK");
            }
        }

        public void Stop()
        {
            listener.Stop();
            listener.Close();
            listener = null;
        }
    }
}
