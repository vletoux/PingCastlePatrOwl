using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;

namespace PingCastlePatrOwlEngine
{
    public class PatrOwlFinding
    {
        public int issue_id { get; set; }
        public string type { get; set; }
        public string title { get; set; }
        public string description { get
            {
                string v = PingCastleTitle;
                if (!string.IsNullOrEmpty(PingCastleTechnicalExplanation))
                    v += "\r\n\r\nTechnical Explanation\r\n\r\n" + PingCastleTechnicalExplanation;
                if (PingCastleDetail != null && PingCastleDetail.Count > 0 && !string.IsNullOrEmpty(PingCastleDetail[0]))
                {
                    var test = PingCastleDetail[0].Replace("Domain controller:", "Domain_controller:").Split(' ');
                    if (test.Length > 1 && test[0].EndsWith(":"))
                    {
                        var tokens = new List<string>();
                        for (int i = 0; i < test.Length; i++)
                        {
                            if (!string.IsNullOrEmpty(test[i]) && test[i].EndsWith(":"))
                            {
                                tokens.Add(test[i]);
                            }
                        }
                        foreach (var token in tokens)
                        {
                            v += (token.Replace("Domain_controller:", "Domain controller:").Substring(0, token.Length - 1));
                        }
                        foreach (var d in PingCastleDetail)
                        {
                            if (string.IsNullOrEmpty(d))
                                continue;
                            v += ("\r\n");
                            var t = d.Replace("Domain controller:", "Domain_controller:").Split(' ');
                            for (int i = 0, j = 0; i < t.Length && j <= tokens.Count; i++)
                            {
                                if (j < tokens.Count && t[i] == tokens[j])
                                {
                                    j++;
                                    if (j != 0)
                                        v += ("\r\n");
                                    v += (tokens[j-1]) + " ";
                                }
                                else
                                {
                                    v += (t[i]);
                                    v += (" ");
                                }
                            }
                            v += ("\r\n");
                        }

                    }
                    else
                    {
                        v += ("\r\n");
                        v += (String.Join("\r\n", PingCastleDetail.ToArray()));
                        v += ("\r\n");
                    }
                }

                return v;
            }
        }

        [JsonIgnore]
        public string PingCastleTitle { get; set; }

        [JsonIgnore]
        public string PingCastleTechnicalExplanation { get; set; }
        [JsonIgnore]
        public List<string> PingCastleDetail { get; set; }

        public string solution { get; set; }
        
        [JsonConverter(typeof(StringEnumConverter))]
        public PatrOwlFindingSeverityEnum severity { get; set; }
        public PatrOwlFindingConfidenceEnum confidence { get; set; }
        public string raw { get; set; }
        public PatrOwlFindingTarget target { get; set; }

        public PatrOwlFindingMetadata metadata { get; set; }

        public DateTime timestamp { get; set; }

    }

    public class PatrOwlFindingVulnRef
    {
        public List<string> cve { get; set; }
        public List<string> cwe { get; set; }
        public List<string> cpe { get; set; }
        public List<string> bid { get; set; }
    }

    public class PatrOwlFindingRisk
    {
        public List<string> cvss_vector { get; set; }
        public List<float> cvss_base_score { get; set; }
        public List<string> exploit_available { get; set; }
        public List<string> exploitability_ease { get; set; }
        public List<string> patch_publication_date { get; set; }
    }

    public class PatrOwlFindingMetadata
    {
        public List<PatrOwlFindingVulnRef> vuln_refs { get; set; }
        public List<PatrOwlFindingRisk> risk { get; set; }
        public List<string> tags { get; set; }
        public List<string> links { get; set; }

    }

    public class PatrOwlFindingTarget
    {
        public List<string> addr { get; set; }
        public List<string> proto { get; set; }
        
    }

    public enum PatrOwlFindingSeverityEnum
    {
        info, 
        low,
        medium, 
        high,
        critical,
    }

    public enum PatrOwlFindingConfidenceEnum
    {
        certain,
    }
}