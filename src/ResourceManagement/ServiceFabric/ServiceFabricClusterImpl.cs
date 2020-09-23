using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Update;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Definition;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.ResourceActions;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.Resource.Definition;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;

using Environment = Microsoft.Azure.Management.ServiceFabric.Fluent.Models.Environment;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Management.Storage.Fluent;

namespace Microsoft.Azure.Management.ServiceFabric.Fluent
{
    /// <summary>
    /// The implementation for ServiceFabricCluster and its create and update interfaces.
    /// </summary>
    internal partial class ServiceFabricClusterImpl :
        GroupableResource<
            IServiceFabricCluster,
            ClusterParameters,
            ServiceFabricClusterImpl,
            IServiceFabricManager,
            IWithGroup,
            IWithWindowsImage,
            IWithCreate,
            IUpdate>,
        IServiceFabricCluster,
        IDefinition,
        IUpdate
    {
        string IIndexable.Key => throw new NotImplementedException();

        public string ClusterState => throw new NotImplementedException();

        internal ServiceFabricClusterImpl(string name, ClusterParameters innerModel, IServiceFabricManager manager)
            : base(name, innerModel, manager)
        {
        }

//.WithReliability(ReliabilityLevel.Silver)
//.WithOneCertificateOnly(clusterCertificate)
//.WithStorageAccountDiagnostics(storageVmDisks)
//.AddNodeType(nodeTypeName)

        public ServiceFabricClusterImpl WindowsImage()
        {
            this.Inner.VmImage = Environment.Windows.ToString();

            return this;
        }

        public string Reliability(Environment environment)
        {
            this.Inner.VmImage = environment.ToString();

            return this.Inner.VmImage;
        }

        public override Task<IServiceFabricCluster> CreateResourceAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        protected override Task<ClusterParameters> GetInnerAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public IWithOneCertificateOnly WithReliability(ReliabilityLevel reliabilityLevel)
        {
            throw new NotImplementedException();
        }

        public IWithStorageAccountDiagnostics WithOneCertificateOnly(X509Certificate2 x509Certificate2)
        {
            throw new NotImplementedException();
        }

        public IAddNodeType WithStorageAccountDiagnostics(IStorageAccount storageAccount)
        {
            throw new NotImplementedException();
        }

        public IWithDefaults AddNodeType(string nodeTypeName)
        {
            throw new NotImplementedException();
        }

        public IWithCreate WithDefaults()
        {
            throw new NotImplementedException();
        }

        ServiceFabricVersion IServiceFabricCluster.Version => throw new NotImplementedException();

        IServiceFabricManager IHasManager<IServiceFabricManager>.Manager => throw new NotImplementedException();

    }
}

