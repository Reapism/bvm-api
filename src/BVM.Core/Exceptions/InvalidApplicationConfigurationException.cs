namespace BVM.Core.Exceptions;
public class InvalidApplicationConfigurationException(string configurationName, string affectedEnvironment) 
    : Exception($"The configuration [{configurationName}] was not found in the appsettings for the affected environment [{affectedEnvironment}].")
{ }

