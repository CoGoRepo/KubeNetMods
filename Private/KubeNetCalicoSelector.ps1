function Get-KubeNetCalicoLabelValue {
    param([object]$Resource, [string]$Key)

    if ($null -eq $Resource -or [string]::IsNullOrWhiteSpace($Key)) { return $null }
    if ($Key -in @('projectcalico.org/name', 'kubernetes.io/metadata.name')) {
        return [string]$Resource.metadata.name
    }
    if ($Key -eq 'projectcalico.org/namespace') {
        return [string]$Resource.metadata.namespace
    }
    $labelProperty = $Resource.metadata.labels.PSObject.Properties[$Key]
    if ($labelProperty) {
        $direct = [string]$labelProperty.Value
        if (-not [string]::IsNullOrWhiteSpace($direct)) { return $direct }
    }

    $calicoMetadata = [string]$Resource.metadata.annotations.'projectcalico.org/metadata'
    if (-not [string]::IsNullOrWhiteSpace($calicoMetadata)) {
        try {
            $decoded = $calicoMetadata | ConvertFrom-Json
            $annotatedProperty = $decoded.labels.PSObject.Properties[$Key]
            if ($annotatedProperty) {
                $annotated = [string]$annotatedProperty.Value
                if (-not [string]::IsNullOrWhiteSpace($annotated)) { return $annotated }
            }
        } catch {
            return $null
        }
    }

    $null
}

function New-KubeNetCalicoSelectorToken {
    param([string]$Kind, [string]$Value = '')
    [PSCustomObject]@{ Kind = $Kind; Value = $Value }
}

function Test-KubeNetCalicoSelectorIdentifierChar {
    param([char]$Char)

    (($Char -ge 'a' -and $Char -le 'z') -or
        ($Char -ge 'A' -and $Char -le 'Z') -or
        ($Char -ge '0' -and $Char -le '9') -or
        $Char -in @('_', '.', '/', '-'))
}

function Read-KubeNetCalicoSelectorIdentifier {
    param([string]$Text, [int]$Index)

    $start = $Index
    while ($Index -lt $Text.Length -and (Test-KubeNetCalicoSelectorIdentifierChar -Char $Text[$Index])) {
        $Index++
    }
    if ($Index -eq $start) {
        throw "expected identifier at position $Index"
    }
    if (($Index - $start) -gt 512) {
        throw "label too long at position $start"
    }
    [PSCustomObject]@{
        Value = $Text.Substring($start, $Index - $start)
        Index = $Index
    }
}

function Read-KubeNetCalicoSelectorString {
    param([string]$Text, [int]$Index)

    $quote = $Text[$Index]
    $start = $Index + 1
    $Index = $start
    while ($Index -lt $Text.Length -and $Text[$Index] -ne $quote) {
        $Index++
    }
    if ($Index -ge $Text.Length) {
        throw 'unterminated string'
    }
    [PSCustomObject]@{
        Value = $Text.Substring($start, $Index - $start)
        Index = $Index + 1
    }
}

function Test-KubeNetCalicoWordBoundary {
    param([string]$Text, [int]$Index)

    if ($Index -ge $Text.Length) { return $true }
    -not (Test-KubeNetCalicoSelectorIdentifierChar -Char $Text[$Index])
}

function ConvertTo-KubeNetCalicoSelectorTokens {
    param([string]$Selector)

    $tokens = @()
    if ($null -eq $Selector) { $Selector = '' }
    $i = 0
    :selectorTokenLoop while ($i -lt $Selector.Length) {
        $c = $Selector[$i]
        if ($c -eq ' ' -or $c -eq "`t") {
            $i++
            continue selectorTokenLoop
        }

        switch ($c) {
            '(' { $tokens += New-KubeNetCalicoSelectorToken -Kind 'LParen'; $i++; continue selectorTokenLoop }
            ')' { $tokens += New-KubeNetCalicoSelectorToken -Kind 'RParen'; $i++; continue selectorTokenLoop }
            '{' { $tokens += New-KubeNetCalicoSelectorToken -Kind 'LBrace'; $i++; continue selectorTokenLoop }
            '}' { $tokens += New-KubeNetCalicoSelectorToken -Kind 'RBrace'; $i++; continue selectorTokenLoop }
            ',' { $tokens += New-KubeNetCalicoSelectorToken -Kind 'Comma'; $i++; continue selectorTokenLoop }
            '"' {
                $read = Read-KubeNetCalicoSelectorString -Text $Selector -Index $i
                $tokens += New-KubeNetCalicoSelectorToken -Kind 'String' -Value $read.Value
                $i = $read.Index
                continue selectorTokenLoop
            }
            "'" {
                $read = Read-KubeNetCalicoSelectorString -Text $Selector -Index $i
                $tokens += New-KubeNetCalicoSelectorToken -Kind 'String' -Value $read.Value
                $i = $read.Index
                continue selectorTokenLoop
            }
            '=' {
                if ($i + 1 -lt $Selector.Length -and $Selector[$i + 1] -eq '=') {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'Eq'
                    $i += 2
                    continue selectorTokenLoop
                }
                throw 'expected =='
            }
            '!' {
                if ($i + 1 -lt $Selector.Length -and $Selector[$i + 1] -eq '=') {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'Ne'
                    $i += 2
                    continue selectorTokenLoop
                }
                $tokens += New-KubeNetCalicoSelectorToken -Kind 'Not'
                $i++
                continue selectorTokenLoop
            }
            '&' {
                if ($i + 1 -lt $Selector.Length -and $Selector[$i + 1] -eq '&') {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'And'
                    $i += 2
                    continue selectorTokenLoop
                }
                throw 'expected &&'
            }
            '|' {
                if ($i + 1 -lt $Selector.Length -and $Selector[$i + 1] -eq '|') {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'Or'
                    $i += 2
                    continue selectorTokenLoop
                }
                throw 'expected ||'
            }
        }

        $lastKind = if ($tokens.Count -gt 0) { $tokens[-1].Kind } else { '' }
        if ($lastKind -eq 'Label') {
            if ($Selector.Substring($i).StartsWith('contains') -and (Test-KubeNetCalicoWordBoundary -Text $Selector -Index ($i + 8))) {
                $tokens += New-KubeNetCalicoSelectorToken -Kind 'Contains'
                $i += 8
                continue selectorTokenLoop
            }
            if ($Selector.Substring($i).StartsWith('starts')) {
                $j = $i + 6
                while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
                if ($Selector.Substring($j).StartsWith('with') -and (Test-KubeNetCalicoWordBoundary -Text $Selector -Index ($j + 4))) {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'StartsWith'
                    $i = $j + 4
                    continue selectorTokenLoop
                }
            }
            if ($Selector.Substring($i).StartsWith('ends')) {
                $j = $i + 4
                while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
                if ($Selector.Substring($j).StartsWith('with') -and (Test-KubeNetCalicoWordBoundary -Text $Selector -Index ($j + 4))) {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'EndsWith'
                    $i = $j + 4
                    continue selectorTokenLoop
                }
            }
            if ($Selector.Substring($i).StartsWith('not')) {
                $j = $i + 3
                while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
                if ($Selector.Substring($j).StartsWith('in') -and (Test-KubeNetCalicoWordBoundary -Text $Selector -Index ($j + 2))) {
                    $tokens += New-KubeNetCalicoSelectorToken -Kind 'NotIn'
                    $i = $j + 2
                    continue selectorTokenLoop
                }
            }
            if ($Selector.Substring($i).StartsWith('in') -and (Test-KubeNetCalicoWordBoundary -Text $Selector -Index ($i + 2))) {
                $tokens += New-KubeNetCalicoSelectorToken -Kind 'In'
                $i += 2
                continue selectorTokenLoop
            }
            throw "expected operator after label '$($tokens[-1].Value)'"
        }

        if ($Selector.Substring($i).StartsWith('has(')) {
            $j = $i + 4
            while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
            $read = Read-KubeNetCalicoSelectorIdentifier -Text $Selector -Index $j
            $j = $read.Index
            while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
            if ($j -ge $Selector.Length -or $Selector[$j] -ne ')') {
                throw "no closing ')' after has("
            }
            $tokens += New-KubeNetCalicoSelectorToken -Kind 'Has' -Value $read.Value
            $i = $j + 1
            continue selectorTokenLoop
        }

        if ($Selector.Substring($i).StartsWith('all(')) {
            $j = $i + 4
            while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
            if ($j -ge $Selector.Length -or $Selector[$j] -ne ')') {
                throw "no closing ')' after all("
            }
            $tokens += New-KubeNetCalicoSelectorToken -Kind 'All'
            $i = $j + 1
            continue selectorTokenLoop
        }

        if ($Selector.Substring($i).StartsWith('global(')) {
            $j = $i + 7
            while ($j -lt $Selector.Length -and ($Selector[$j] -eq ' ' -or $Selector[$j] -eq "`t")) { $j++ }
            if ($j -ge $Selector.Length -or $Selector[$j] -ne ')') {
                throw "no closing ')' after global("
            }
            $tokens += New-KubeNetCalicoSelectorToken -Kind 'Global'
            $i = $j + 1
            continue selectorTokenLoop
        }

        $readIdent = Read-KubeNetCalicoSelectorIdentifier -Text $Selector -Index $i
        $tokens += New-KubeNetCalicoSelectorToken -Kind 'Label' -Value $readIdent.Value
        $i = $readIdent.Index
    }

    $tokens += New-KubeNetCalicoSelectorToken -Kind 'EOF'
    @($tokens)
}

function New-KubeNetCalicoSelectorNode {
    param([string]$Type, [string]$Label = '', [string]$Value = '', [string[]]$Values = @(), [object[]]$Children = @())
    [PSCustomObject]@{
        Type     = $Type
        Label    = $Label
        Value    = $Value
        Values   = @($Values)
        Children = @($Children)
    }
}

function Read-KubeNetCalicoSelectorOrExpression {
    param([object[]]$Tokens, [ref]$Index)

    $children = @((Read-KubeNetCalicoSelectorAndExpression -Tokens $Tokens -Index $Index))
    while ($Tokens[$Index.Value].Kind -eq 'Or') {
        $Index.Value++
        $children += Read-KubeNetCalicoSelectorAndExpression -Tokens $Tokens -Index $Index
    }
    if ($children.Count -eq 1) { return $children[0] }
    New-KubeNetCalicoSelectorNode -Type 'Or' -Children $children
}

function Read-KubeNetCalicoSelectorAndExpression {
    param([object[]]$Tokens, [ref]$Index)

    $children = @((Read-KubeNetCalicoSelectorOperation -Tokens $Tokens -Index $Index))
    while ($Tokens[$Index.Value].Kind -eq 'And') {
        $Index.Value++
        $children += Read-KubeNetCalicoSelectorOperation -Tokens $Tokens -Index $Index
    }
    if ($children.Count -eq 1) { return $children[0] }
    New-KubeNetCalicoSelectorNode -Type 'And' -Children $children
}

function Read-KubeNetCalicoSelectorOperation {
    param([object[]]$Tokens, [ref]$Index)

    $negated = $false
    while ($Tokens[$Index.Value].Kind -eq 'Not') {
        $negated = -not $negated
        $Index.Value++
    }

    $token = $Tokens[$Index.Value]
    switch ($token.Kind) {
        'Has' {
            $node = New-KubeNetCalicoSelectorNode -Type 'Has' -Label $token.Value
            $Index.Value++
        }
        'All' {
            $node = New-KubeNetCalicoSelectorNode -Type 'All'
            $Index.Value++
        }
        'Global' {
            $node = New-KubeNetCalicoSelectorNode -Type 'Global'
            $Index.Value++
        }
        'LParen' {
            $Index.Value++
            $node = Read-KubeNetCalicoSelectorOrExpression -Tokens $Tokens -Index $Index
            if ($Tokens[$Index.Value].Kind -ne 'RParen') { throw 'expected )' }
            $Index.Value++
        }
        'Label' {
            if (($Index.Value + 2) -ge $Tokens.Count) { throw 'unexpected end of string looking for op' }
            $label = $token.Value
            $op = $Tokens[$Index.Value + 1]
            switch ($op.Kind) {
                'Eq' {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'String') { throw 'expected string' }
                    $node = New-KubeNetCalicoSelectorNode -Type 'Eq' -Label $label -Value $Tokens[$Index.Value + 2].Value
                    $Index.Value += 3
                }
                'Ne' {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'String') { throw 'expected string' }
                    $node = New-KubeNetCalicoSelectorNode -Type 'Ne' -Label $label -Value $Tokens[$Index.Value + 2].Value
                    $Index.Value += 3
                }
                'Contains' {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'String') { throw 'expected string' }
                    $node = New-KubeNetCalicoSelectorNode -Type 'Contains' -Label $label -Value $Tokens[$Index.Value + 2].Value
                    $Index.Value += 3
                }
                'StartsWith' {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'String') { throw 'expected string' }
                    $node = New-KubeNetCalicoSelectorNode -Type 'StartsWith' -Label $label -Value $Tokens[$Index.Value + 2].Value
                    $Index.Value += 3
                }
                'EndsWith' {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'String') { throw 'expected string' }
                    $node = New-KubeNetCalicoSelectorNode -Type 'EndsWith' -Label $label -Value $Tokens[$Index.Value + 2].Value
                    $Index.Value += 3
                }
                { $_ -in @('In', 'NotIn') } {
                    if ($Tokens[$Index.Value + 2].Kind -ne 'LBrace') { throw 'expected set literal' }
                    $Index.Value += 3
                    $values = @()
                    while ($Tokens[$Index.Value].Kind -eq 'String') {
                        $values += [string]$Tokens[$Index.Value].Value
                        $Index.Value++
                        if ($Tokens[$Index.Value].Kind -eq 'Comma') {
                            $Index.Value++
                        } else {
                            break
                        }
                    }
                    if ($Tokens[$Index.Value].Kind -ne 'RBrace') { throw 'expected }' }
                    $nodeType = if ($op.Kind -eq 'In') { 'In' } else { 'NotIn' }
                    $node = New-KubeNetCalicoSelectorNode -Type $nodeType -Label $label -Values $values
                    $Index.Value++
                }
                default {
                    throw "expected == or != not: $($op.Kind)"
                }
            }
        }
        default {
            throw "unexpected token: $($token.Kind)"
        }
    }

    if ($negated) {
        $node = New-KubeNetCalicoSelectorNode -Type 'Not' -Children @($node)
    }
    $node
}

function ConvertFrom-KubeNetCalicoSelector {
    param([string]$Selector)

    $tokens = ConvertTo-KubeNetCalicoSelectorTokens -Selector $Selector
    if ($tokens[0].Kind -eq 'EOF') {
        return New-KubeNetCalicoSelectorNode -Type 'All'
    }
    $index = 0
    $node = Read-KubeNetCalicoSelectorOrExpression -Tokens $tokens -Index ([ref]$index)
    if ($tokens[$index].Kind -ne 'EOF') {
        throw "unexpected content at end of selector: $($tokens[$index].Kind)"
    }
    $node
}

function Test-KubeNetCalicoSelectorNode {
    param([object]$Node, [object]$Resource)

    switch ($Node.Type) {
        'All' { return $true }
        'Global' { return [string]::IsNullOrWhiteSpace([string]$Resource.metadata.namespace) }
        'Has' { return -not [string]::IsNullOrWhiteSpace((Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label)) }
        'Eq' { return (Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label) -eq $Node.Value }
        'Ne' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return [string]::IsNullOrWhiteSpace($actual) -or $actual -ne $Node.Value
        }
        'In' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return -not [string]::IsNullOrWhiteSpace($actual) -and @($Node.Values) -contains $actual
        }
        'NotIn' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return [string]::IsNullOrWhiteSpace($actual) -or -not (@($Node.Values) -contains $actual)
        }
        'Contains' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return -not [string]::IsNullOrWhiteSpace($actual) -and $actual.Contains($Node.Value)
        }
        'StartsWith' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return -not [string]::IsNullOrWhiteSpace($actual) -and $actual.StartsWith($Node.Value)
        }
        'EndsWith' {
            $actual = Get-KubeNetCalicoLabelValue -Resource $Resource -Key $Node.Label
            return -not [string]::IsNullOrWhiteSpace($actual) -and $actual.EndsWith($Node.Value)
        }
        'Not' { return -not (Test-KubeNetCalicoSelectorNode -Node $Node.Children[0] -Resource $Resource) }
        'And' {
            foreach ($child in @($Node.Children)) {
                if (-not (Test-KubeNetCalicoSelectorNode -Node $child -Resource $Resource)) { return $false }
            }
            return $true
        }
        'Or' {
            foreach ($child in @($Node.Children)) {
                if (Test-KubeNetCalicoSelectorNode -Node $child -Resource $Resource) { return $true }
            }
            return $false
        }
        default {
            throw "unsupported selector node type '$($Node.Type)'"
        }
    }
}

function Test-KubeNetCalicoSelectorHasUnbalancedQuotes {
    param([string]$Selector)

    if ([string]::IsNullOrWhiteSpace($Selector)) { return $false }
    $singleQuoteCount = 0
    $doubleQuoteCount = 0
    foreach ($char in $Selector.ToCharArray()) {
        if ($char -eq "'") { $singleQuoteCount++ }
        if ($char -eq '"') { $doubleQuoteCount++ }
    }
    (($singleQuoteCount % 2) -ne 0) -or (($doubleQuoteCount % 2) -ne 0)
}

function Test-KubeNetCalicoSelectorCanParse {
    param([string]$Selector)

    try {
        ConvertFrom-KubeNetCalicoSelector -Selector $Selector | Out-Null
        $true
    } catch {
        $false
    }
}

function Test-KubeNetCalicoSelector {
    param([string]$Selector, [object]$Resource)

    try {
        $node = ConvertFrom-KubeNetCalicoSelector -Selector $Selector
        Test-KubeNetCalicoSelectorNode -Node $node -Resource $Resource
    } catch {
        $false
    }
}
