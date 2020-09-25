using Microsoft.Azure.Management.Storage.Fluent;
using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Azure.Management.ServiceFabric.Fluent
{
    internal partial class ServiceFabricClusterImpl
    {
        ServiceFabricCluster.Definition.IWithReliabilityLevel ServiceFabricCluster.Definition.IWithWindowsImage.WithWindowsImage()
        {
            return this.WindowsImage();
        }

        ServiceFabricCluster.Definition.IWithOneCertificateOnly ServiceFabricCluster.Definition.IWithReliabilityLevel.WithReliabilityLevel(ReliabilityLevel reliabilityLevel)
        {
            return this.ReliabilityLevel(reliabilityLevel);
        }

        ServiceFabricCluster.Definition.IWithStorageAccountDiagnostics ServiceFabricCluster.Definition.IWithOneCertificateOnly.WithOneCertificateOnly(X509Certificate2 certificate)
        {
            return this.WithOneCertificateOnly(certificate);
        }

        ServiceFabricCluster.Definition.IAddNodeType ServiceFabricCluster.Definition.IWithStorageAccountDiagnostics.WithStorageAccountDiagnostics(IStorageAccount storageAccount)
        {
            return this.WithStorageAccountDiagnostics(storageAccount);
        }

        ServiceFabricCluster.Definition.IWithDefaults ServiceFabricCluster.Definition.IAddNodeType.AddNodeType(string nodeTypeName)
        {
            return this.AddNodeType(nodeTypeName);
        }

        ServiceFabricCluster.Definition.IWithCreate ServiceFabricCluster.Definition.IWithDefaults.WithDefaults()
        {
            return this.WithDefaults();
        }

        //async Task<Microsoft.Azure.Management.ServiceFabric.Fluent.IServiceFabricCluster> Microsoft.Azure.Management.ResourceManager.Fluent.Core.ResourceActions.IRefreshable<Microsoft.Azure.Management.ServiceFabric.Fluent.IServiceFabricCluster>.RefreshAsync(CancellationToken cancellationToken)
        //{
        //    return await this.RefreshAsync(cancellationToken);
        //}

        //public override IServiceFabricCluster Refresh()
        //{
        //    return base.Refresh();
        //}

        protected override Task<ClusterParameters> GetInnerAsync(CancellationToken cancellationToken)
        {
            return this.GetInnerAsync(cancellationToken);
        }
    }
}
