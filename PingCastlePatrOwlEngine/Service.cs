using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PingCastlePatrOwlEngine
{
    public partial class Service : ServiceBase
    {
        Listener listener = null;

        public Service()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            listener = new Listener();
            listener.Start();
        }

        

        protected override void OnStop()
        {
            if (listener != null)
            {
                listener.Stop();
                listener = null;
            }
        }
    }
}
