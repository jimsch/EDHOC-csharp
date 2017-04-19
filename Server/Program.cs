using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP;
using Com.AugustCellars.CoAP.Server;
using Com.AugustCellars.CoAP.EDHOC;

namespace Server
{
    class Program
    {
        static void Main(string[] args)
        {
            CoapServer server = new CoapServer();

            server.Add(new EdhocResource(null, null));

            server.Start();

            Console.WriteLine("Press key to exit");
            Console.ReadKey();
        }
    }
}
