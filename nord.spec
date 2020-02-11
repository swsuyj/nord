Name:           nord
Version:        0.1
Release:        1%{?dist}
Summary:        A command line application for NordVPN

License:        GPLv3+
URL:            https://github.com/swsuyj/%{name}
Source0:        %{_sourcedir}/%{name}-%{version}-%{release}.tar.gz
BuildArch:      noarch

Requires:       firewalld
Requires:       bash
Requires:       wget
Requires:       unzip
Requires:       sed
Requires:       NetworkManager-openvpn

%description
Nord is a command line application written in Bash
with few/no dependencies.


%prep


%build
cp %{name} %{_sourcedir}


%install
mkdir -p %{buildroot}%{_bindir}
sudo install -m 755 %{name} %{buildroot}%{_bindir}


%check


%files
%license LICENCE
%doc %{_mandir}/%{name}.1
%{_bindir}/%{name}


%changelog
* Sun Feb 09 2020 swsuyj <> - 0.1-1
- Initial version of the package

