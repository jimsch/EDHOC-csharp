using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP.Server.Resources;

namespace Com.AugustCellars.CoAP.EDHOC.Test
{
    class Hello : Resource
    {
        public Hello(String name) : base(name)
        {
            Attributes.Title = "GET a friendly string";
            Attributes.AddResourceType("HelloWorldDisplayer");
            RequireSecurity = true;
        }

        protected override void DoGet(CoapExchange exchange)
        {
            exchange.Respond("Hello World!");
        }
    }
}
