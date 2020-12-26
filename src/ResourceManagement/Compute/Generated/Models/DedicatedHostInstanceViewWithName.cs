// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Compute.Fluent.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// The instance view of a dedicated host that includes the name of the
    /// dedicated host. It is used for the response to the instance view of a
    /// dedicated host group.
    /// </summary>
    public partial class DedicatedHostInstanceViewWithName : DedicatedHostInstanceView
    {
        /// <summary>
        /// Initializes a new instance of the DedicatedHostInstanceViewWithName
        /// class.
        /// </summary>
        public DedicatedHostInstanceViewWithName()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the DedicatedHostInstanceViewWithName
        /// class.
        /// </summary>
        /// <param name="assetId">Specifies the unique id of the dedicated
        /// physical machine on which the dedicated host resides.</param>
        /// <param name="availableCapacity">Unutilized capacity of the
        /// dedicated host.</param>
        /// <param name="statuses">The resource status information.</param>
        /// <param name="name">The name of the dedicated host.</param>
        public DedicatedHostInstanceViewWithName(string assetId = default(string), DedicatedHostAvailableCapacity availableCapacity = default(DedicatedHostAvailableCapacity), IList<InstanceViewStatus> statuses = default(IList<InstanceViewStatus>), string name = default(string))
            : base(assetId, availableCapacity, statuses)
        {
            Name = name;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets the name of the dedicated host.
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; private set; }

    }
}
