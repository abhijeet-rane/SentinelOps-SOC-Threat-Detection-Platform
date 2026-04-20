namespace SOCPlatform.Detection.Rules.Advanced;

/// <summary>
/// Compact table of the top-150 most common English letter bigrams (a-z only).
/// Frequencies are from Peter Norvig's public-domain analysis of the Google
/// Web-Trillion-Word corpus (www.norvig.com/mayzner.html), truncated for brevity.
/// Unknown bigrams fall through to a floor so scores don't explode.
/// </summary>
internal static class EnglishBigramFrequency
{
    // Floor for unknown bigrams. Set so that a normal English word (microsoft,
    // wikipedia, stackoverflow) still scores above the DGA threshold even when
    // several of its bigrams aren't in the truncated top-150 table.
    private const double Floor = 0.001;

    // Percentages (fractional) — sum is less than 1.0 because we only store the top ~150.
    private static readonly Dictionary<string, double> Map = new()
    {
        ["th"] = 0.0356, ["he"] = 0.0307, ["in"] = 0.0243, ["er"] = 0.0205, ["an"] = 0.0199,
        ["re"] = 0.0185, ["on"] = 0.0176, ["at"] = 0.0149, ["en"] = 0.0145, ["nd"] = 0.0135,
        ["ti"] = 0.0134, ["es"] = 0.0134, ["or"] = 0.0128, ["te"] = 0.0120, ["of"] = 0.0116,
        ["ed"] = 0.0117, ["is"] = 0.0113, ["it"] = 0.0112, ["al"] = 0.0109, ["ar"] = 0.0107,
        ["st"] = 0.0105, ["to"] = 0.0105, ["nt"] = 0.0104, ["ng"] = 0.0095, ["se"] = 0.0093,
        ["ha"] = 0.0093, ["as"] = 0.0087, ["ou"] = 0.0087, ["io"] = 0.0083, ["le"] = 0.0083,
        ["ve"] = 0.0083, ["co"] = 0.0079, ["me"] = 0.0079, ["de"] = 0.0076, ["hi"] = 0.0076,
        ["ri"] = 0.0073, ["ro"] = 0.0073, ["ic"] = 0.0070, ["ne"] = 0.0069, ["ea"] = 0.0069,
        ["ra"] = 0.0069, ["ce"] = 0.0065, ["li"] = 0.0062, ["ch"] = 0.0060, ["ll"] = 0.0058,
        ["be"] = 0.0058, ["ma"] = 0.0057, ["si"] = 0.0055, ["om"] = 0.0055, ["ur"] = 0.0054,
        ["ca"] = 0.0054, ["el"] = 0.0052, ["ta"] = 0.0051, ["la"] = 0.0050, ["ns"] = 0.0050,
        ["di"] = 0.0050, ["fo"] = 0.0050, ["ho"] = 0.0049, ["pe"] = 0.0048, ["ec"] = 0.0048,
        ["pr"] = 0.0048, ["no"] = 0.0047, ["ct"] = 0.0046, ["us"] = 0.0045, ["ac"] = 0.0045,
        ["ot"] = 0.0044, ["il"] = 0.0043, ["tr"] = 0.0043, ["ly"] = 0.0042, ["nc"] = 0.0042,
        ["et"] = 0.0042, ["ut"] = 0.0042, ["ss"] = 0.0041, ["so"] = 0.0040, ["rs"] = 0.0039,
        ["un"] = 0.0037, ["lo"] = 0.0037, ["wa"] = 0.0037, ["ge"] = 0.0036, ["ie"] = 0.0036,
        ["wh"] = 0.0036, ["ee"] = 0.0035, ["wi"] = 0.0035, ["em"] = 0.0035, ["ad"] = 0.0034,
        ["ol"] = 0.0034, ["rt"] = 0.0034, ["po"] = 0.0033, ["we"] = 0.0033, ["na"] = 0.0032,
        ["ul"] = 0.0032, ["ni"] = 0.0032, ["ts"] = 0.0032, ["mo"] = 0.0031, ["ow"] = 0.0031,
        ["pa"] = 0.0031, ["im"] = 0.0031, ["mi"] = 0.0030, ["ai"] = 0.0030, ["sh"] = 0.0030,
        ["ir"] = 0.0029, ["su"] = 0.0029, ["id"] = 0.0029, ["os"] = 0.0029, ["iv"] = 0.0029,
        ["ia"] = 0.0028, ["am"] = 0.0028, ["fi"] = 0.0028, ["ci"] = 0.0028, ["vi"] = 0.0027,
        ["pl"] = 0.0027, ["ig"] = 0.0027, ["tu"] = 0.0026, ["ev"] = 0.0026, ["ld"] = 0.0024,
        ["ry"] = 0.0024, ["mp"] = 0.0023, ["fe"] = 0.0023, ["bl"] = 0.0023, ["ab"] = 0.0023,
        ["gh"] = 0.0023, ["ty"] = 0.0023, ["op"] = 0.0022, ["wo"] = 0.0022, ["sa"] = 0.0022,
        ["ay"] = 0.0021, ["ex"] = 0.0021, ["ke"] = 0.0021, ["fr"] = 0.0021, ["oo"] = 0.0021,
        ["av"] = 0.0020, ["ag"] = 0.0020, ["if"] = 0.0020, ["ap"] = 0.0020, ["gr"] = 0.0020,
        ["od"] = 0.0020, ["bo"] = 0.0020, ["sp"] = 0.0020, ["rd"] = 0.0019, ["do"] = 0.0019,
        ["uc"] = 0.0019, ["bu"] = 0.0019, ["ei"] = 0.0019, ["ov"] = 0.0019, ["by"] = 0.0019,
        ["rm"] = 0.0018, ["ep"] = 0.0018, ["tt"] = 0.0018, ["oc"] = 0.0018, ["fa"] = 0.0018,
        ["ef"] = 0.0018, ["cu"] = 0.0018, ["rn"] = 0.0018
    };

    public static double LookupOrFloor(string bigram) =>
        Map.TryGetValue(bigram.ToLowerInvariant(), out var f) ? f : Floor;
}
