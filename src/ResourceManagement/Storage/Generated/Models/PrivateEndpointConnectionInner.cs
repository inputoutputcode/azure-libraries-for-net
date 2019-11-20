// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Storage.Fluent.Models
{
    using Microsoft.Azure.Management.ResourceManager;
    using Microsoft.Azure.Management.ResourceManager.Fluent;
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The Private Endpoint Connection resource.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class PrivateEndpointConnectionInner : Management.ResourceManager.Fluent.Resource
    {
        /// <summary>
        /// Initializes a new instance of the PrivateEndpointConnectionInner
        /// class.
        /// </summary>
        public PrivateEndpointConnectionInner()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the PrivateEndpointConnectionInner
        /// class.
        /// </summary>
        /// <param name="privateLinkServiceConnectionState">A collection of
        /// information about the state of the connection between service
        /// consumer and provider.</param>
        /// <param name="privateEndpoint">The resource of private end
        /// point.</param>
        /// <param name="provisioningState">The provisioning state of the
        /// private endpoint connection resource. Possible values include:
        /// 'Succeeded', 'Creating', 'Deleting', 'Failed'</param>
        public PrivateEndpointConnectionInner(PrivateLinkServiceConnectionState privateLinkServiceConnectionState, string id = default(string), string name = default(string), string type = default(string), PrivateEndpoint privateEndpoint = default(PrivateEndpoint), PrivateEndpointConnectionProvisioningState provisioningState = default(PrivateEndpointConnectionProvisioningState))
            : base(id, name, type)
        {
            PrivateEndpoint = privateEndpoint;
            PrivateLinkServiceConnectionState = privateLinkServiceConnectionState;
            ProvisioningState = provisioningState;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the resource of private end point.
        /// </summary>
        [JsonProperty(PropertyName = "properties.privateEndpoint")]
        public PrivateEndpoint PrivateEndpoint { get; set; }

        /// <summary>
        /// Gets or sets a collection of information about the state of the
        /// connection between service consumer and provider.
        /// </summary>
        [JsonProperty(PropertyName = "properties.privateLinkServiceConnectionState")]
        public PrivateLinkServiceConnectionState PrivateLinkServiceConnectionState { get; set; }

        /// <summary>
        /// Gets or sets the provisioning state of the private endpoint
        /// connection resource. Possible values include: 'Succeeded',
        /// 'Creating', 'Deleting', 'Failed'
        /// </summary>
        [JsonProperty(PropertyName = "properties.provisioningState")]
        public PrivateEndpointConnectionProvisioningState ProvisioningState { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (PrivateLinkServiceConnectionState == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "PrivateLinkServiceConnectionState");
            }
        }
    }
}