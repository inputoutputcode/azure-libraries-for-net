// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

using Microsoft.Azure.Management.ResourceManager.Fluent.Core;

namespace Microsoft.Azure.Management.ContainerRegistry.Fluent.Models
{
    /// <summary>
    /// Defines values for SourceControlType.
    /// </summary>
    public partial class SourceControlType : ExpandableStringEnum<SourceControlType>, IBeta
    {
        /// <summary>
        /// Static value Github for SourceControlType.
        /// </summary>
        public static readonly SourceControlType Github = Parse("Github");

        /// <summary>
        /// Static value VisualStudioTeamService for SourceControlType.
        /// </summary>
        public static readonly SourceControlType VisualStudioTeamService = Parse("VisualStudioTeamService");
    }
}
