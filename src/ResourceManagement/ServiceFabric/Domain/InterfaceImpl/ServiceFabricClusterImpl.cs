using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Definition;


namespace Microsoft.Azure.Management.ServiceFabric.Fluent.Domain.InterfaceImpl
{
    internal partial class ServiceFabricClusterImpl
    {
        string IWithVmImage.VmImage
        {
            get 
            {
               return this.VmImage();
            }
        }

    }
}
