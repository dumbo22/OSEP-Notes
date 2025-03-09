using System.Net;

namespace Program
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                WebRequest request = WebRequest.Create("http://NotARealDomainPLS/default.html");
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Environment.Exit(0);
                }
            }
            catch
            {}
        }
    }
}
