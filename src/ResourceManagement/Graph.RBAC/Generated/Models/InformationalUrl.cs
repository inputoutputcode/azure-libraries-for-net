// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Graph.RBAC.Fluent.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// Represents a group of URIs that provide terms of service, marketing,
    /// support and privacy policy information about an application. The
    /// default value for each string is null.
    /// </summary>
    public partial class InformationalUrl
    {
        /// <summary>
        /// Initializes a new instance of the InformationalUrl class.
        /// </summary>
        public InformationalUrl()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the InformationalUrl class.
        /// </summary>
        /// <param name="termsOfService">The terms of service URI</param>
        /// <param name="marketing">The marketing URI</param>
        /// <param name="privacy">The privacy policy URI</param>
        /// <param name="support">The support URI</param>
        public InformationalUrl(string termsOfService = default(string), string marketing = default(string), string privacy = default(string), string support = default(string))
        {
            TermsOfService = termsOfService;
            Marketing = marketing;
            Privacy = privacy;
            Support = support;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the terms of service URI
        /// </summary>
        [JsonProperty(PropertyName = "termsOfService")]
        public string TermsOfService { get; set; }

        /// <summary>
        /// Gets or sets the marketing URI
        /// </summary>
        [JsonProperty(PropertyName = "marketing")]
        public string Marketing { get; set; }

        /// <summary>
        /// Gets or sets the privacy policy URI
        /// </summary>
        [JsonProperty(PropertyName = "privacy")]
        public string Privacy { get; set; }

        /// <summary>
        /// Gets or sets the support URI
        /// </summary>
        [JsonProperty(PropertyName = "support")]
        public string Support { get; set; }

    }
}
