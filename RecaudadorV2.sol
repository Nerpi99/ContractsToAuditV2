//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import "hardhat/console.sol";

/// @title Interface to call QuickSwap Router
/// @dev Used to swap tokens
interface UniswapV2Router02 {
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external payable returns (uint256[] memory amounts);
}

/// @title Interface to call Roles contract
/// @notice Used to grant a role when buying
/// @dev Manage acces control in the application
interface IRoles {
    function hasRole(bytes32 role, address account)
        external
        view
        returns (bool);

    function getHashRole(string calldata _roleName)
        external
        view
        returns (bytes32);

    function grantRole(bytes32 role, address beneficiary) external;
}

/// @title Contract used to receive pays and register the amount of NFTs corresponding to a client
/// @author Dapps Factory
/// @notice This contract is used to offer a pre sale of NFTs at special price
/// @dev Should have an owner
contract RecaudadorV2 is
    Initializable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{   
    /// @notice DEPRECATED
    /// @dev DEPRECATED VARIABLE, isnt deleted because storage layout
    /// @return oracleAddress renamed to priceFeed in new version 
    address public oracleAddress; // matic/usd

    /// @notice Address of the token used to swap the MATIC payed
    /// @dev Token used for internal swap
    /// @return TOKENADDRESS address of the token used
    address public TOKENADDRESS;

    /// @notice Address of WMATIC
    /// @dev address used in the router path to swap tokens
    /// @return MATIC address of WMatic
    address public MATIC;

    /// @notice DEPRECATED
    /// @dev DEPRECATED VARIABLE, isnt deleted because storage layout
    /// @return ROUTER variable unused in version 2
    address public ROUTER; // QUICKSWAP ROUTER


    /// @notice Wallet that should receive the pay of the NFTs selled
    /// @dev This address should receive token of type TOKENADDRESS
    /// @return walletRecaudadora address of the collector wallet
    address public walletRecaudadora;

    /// @notice Max amount of NFTs to sell by this contract
    /// @dev Used to revert if there is no more NFTs at sell
    /// @return maxNftAmount the max amount of NFTs to sell
    uint256 public maxNftAmount;

    /// @notice NFTs already sold
    /// @dev Counter to know how many NFTs already been sold
    /// @return nftSold the amount of NFTs sold
    uint256 public nftSold;

    /// @notice Price of 1 NFT in USD represented in Weis
    /// @dev Some arithmetic is made from this variable
    /// @return usdPrice the USD amount that 1 NFT cost in weis 
    uint256 public usdPrice;

    /// @notice NFT that already been claimed by the users
    /// @dev Used to check some information
    /// @return nftsRedeemed the amont of NFTs that were sold and also claimed
    uint256 public nftsRedeemed;

    /// @notice Slippage used to swap the pay from a client to a stablecoin 
    /// @dev The range of this variable is 1 to 1000, were the value 1000 is equal to 100%. Inital value is set in 10 = 1% of slippage
    /// @return slippagePorcentual the value of the setted slippage
    uint256 public slippagePorcentual;

    /// @notice Oracle variable to check the price of MATIC
    /// @dev Used to ask the MATIC price in usd and compute the value of a NFT
    /// @return priceFeed return the address of the oracle
    AggregatorV3Interface public priceFeed;

    /// @notice Address of a router to make a swap
    /// @dev Used internally to swap a pay received in MATIC to USDC
    /// @return router address of the router used
    UniswapV2Router02 public router;

    /// @notice Address of Roles contract that manage access control
    /// @dev This contract is used to grant roles and restrict some calls and access 
    /// @return roles the address of the Roles contract
    IRoles public roles;

    //PATRON REGISTRO DE ADDRESS E INFORMACION *************
    //estructura que posee informacion sobre los nfts que un cliente compro y reclamo
    struct ClientInfo {
        uint256 nftsPresalePurchased;
        uint256 claimedNfts;
    }
    mapping(address => ClientInfo) private clientInfo; //mapping que registra los address con estructura
    address[] private clients; //array para tener registro de cantidad de clientes
    //******************** FIN PATRON

    /// @notice Matic Transacted by this contract
    /// @dev Counter to keep track of the matic raised
    /// @return maticTransacted the amount of matic raised
    uint256 public maticTransacted;

    /// @notice USDC raised by this contract
    /// @dev Counter to keep track of the USDC raised, it is returned in 6 decimals
    /// @return usdcRaised the amount of USDC raised
    uint256 public usdcRaised;

    /// @notice Event emited to register buyers info
    /// @dev Event for saving info
    /// @param wallet  Address that buy NFTs
    /// @param nftAmount  Amount of NFTs that the wallet bougth
    /// @param usdcAmount  Amount of USDC that went to the collector address
    /// @param maticAmount  Amount of MATIC that the client pay
    event Purchase(
        address indexed wallet,
        uint256 nftAmount,
        uint256 usdcAmount,
        uint256 maticAmount
    );

    /// @notice Event to catch when the owner is change
    /// @dev Used to monitor the security of the ownership
    /// @param previousCollector address of the former collector
    /// @param newCollector address of the new collector
    /// @param msgSender address to notice who changes the ownership
    event CollectorChanged(address indexed previousCollector, address indexed newCollector, address msgSender);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /* _priceOfNft: precio del nft en dolares expresado en Weis (18 decimales/ 10**18), 1 dolar = 1000000000000000000 weis
        _nftAmount: cantidad de nfts a la venta, se expresa en numeros enteros
        _roles: address del contrato de roles deployado por Dapps Factory
     */
     /// @notice Function to initialize the Proxy Contract
     /// @dev Initalize the initial state of the contract
     /// @param _walletRecaudadora collector wallet
     /// @param _nftAmount amount of NFT in sell
     /// @param _priceOfNft price of 1 NFT in USD passed in weis
     /// @param _roles address of the contract that manage access control in the app
    function initialize(
        address _walletRecaudadora,
        uint256 _nftAmount,
        uint256 _priceOfNft,
        address _roles
    ) external initializer {
        __ReentrancyGuard_init();
        __Ownable_init();
        __Pausable_init();
        require(_walletRecaudadora != address(0), "address 0");
        require(_priceOfNft > 0, "Price cannot be 0");
        require(_roles != address(0), "Roles cannot be address 0");
        usdPrice = _priceOfNft; // viene en wei => 1.47usd = 1470000000000000000usd
        priceFeed = AggregatorV3Interface(0xAB594600376Ec9fD91F8e885dADF0CE036862dE0);
        roles = IRoles(_roles);
        router = UniswapV2Router02(0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff);
        walletRecaudadora = _walletRecaudadora;
        maxNftAmount = _nftAmount;
        TOKENADDRESS = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174; // usdc
        MATIC = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270; // WMATIC
        slippagePorcentual = 10; //el valor 10 significa el 1%, se calcula como slippagePorcentual/1000. 
    }

    receive() external payable {}

    /// @notice Function used to buy just 1 nft
    /// @dev Shouldn´t be called outside the web-site, check that msg.value is greater than the price of 1 NFT, contract must be unpaused
    /// @dev Grant a buyer role once for each caller, update the registry of NFTs sold. Swap and send the pay to the collector wallet in StableCoin
    function buy() external payable nonReentrant whenNotPaused {
        uint256 nftPrice = computeAmount();
        require(msg.value >= nftPrice, "Insufficient founds");
        require(nftSold + 1 <= maxNftAmount, "Insuficient Nfts for sell"); // lo que compra sumado a lo que se vendio tiene que ser menor al maximo
        if (clientInfo[msg.sender].nftsPresalePurchased == 0) {
            // Agrega por unica vez al array y da el rol una unica vez
            clients.push(msg.sender);
            roles.grantRole(keccak256("PRE_SALE_NFT_BUYER"), msg.sender);
        }
        clientInfo[msg.sender].nftsPresalePurchased++;
        nftSold++;
        uint256 amountUsdcTransfered = _swapTokens(msg.value); //se transfieren usdc a la wallet recaudadora
        maticTransacted += msg.value;
        usdcRaised += amountUsdcTransfered;
        emit Purchase(msg.sender, 1, amountUsdcTransfered, msg.value);
    }

    /// @notice Function used to buy a predeterminated amount of NFTs
    /// @dev Check that msg.value is greater than the price of the NFTs parameter, check some conditions for the sell, contract must be unpaused
    /// @dev Grant a buyer role once for each caller, update the registry of NFTs sold. Swap and send the pay to the collector wallet in StableCoin
    /// @param _amountOfNfts amount of NFTs that the buyers wants
    function buyFixedNftAmount(uint256 _amountOfNfts) external payable nonReentrant whenNotPaused {
        require(_amountOfNfts > 0, "Invalid NFT amount");
        uint256 nftPrice = computeAmount(); // calcula el precio de 1 NFT en MATIC
        require(msg.value >= nftPrice * _amountOfNfts, "Insufficient founds");
        require(nftSold + _amountOfNfts <= maxNftAmount, "Insuficient Nfts for sell"); // lo que compra sumado a lo que se vendio tiene que ser menor al maximo
        if (clientInfo[msg.sender].nftsPresalePurchased == 0) {
            // Agrega por unica vez al array y da el rol una unica vez
            clients.push(msg.sender);
            roles.grantRole(keccak256("PRE_SALE_NFT_BUYER"), msg.sender);
        }
        clientInfo[msg.sender].nftsPresalePurchased += _amountOfNfts;
        nftSold += _amountOfNfts;
        maticTransacted += nftPrice * _amountOfNfts;
        uint256 amountUsdcTransfered = _swapTokens(nftPrice * _amountOfNfts); //se transfieren usdc a la wallet recaudadora
        usdcRaised += amountUsdcTransfered;
        uint256 surplus = msg.value - (nftPrice * _amountOfNfts);
        if(surplus > 0){
            require(address(this).balance > 0, "Insuficient funds");
            (bool success, ) = msg.sender.call{value: surplus }("");
            require(success, "Forward funds fail");
        }
        emit Purchase(msg.sender, _amountOfNfts, amountUsdcTransfered, nftPrice*_amountOfNfts);
    }

    /// @notice Function used to invest an amount of MATIC
    /// @dev Check that the msg.value is greater than the value of 1 NFT, compute the amount of NFTs and returns the surplus if any, contract must be unpaused
    /// @dev Grant a buyer role once for each caller, update the registry of NFTs sold. Swap and send the pay to the collector wallet in StableCoin
    function buyFixedMaticAmount() external payable nonReentrant whenNotPaused {
        uint256 nftPrice = computeAmount();
        require(msg.value > nftPrice,"Must send more than the price of 1 nft");
        uint256 amountOfNfts = msg.value / nftPrice;
        require(nftSold + amountOfNfts <= maxNftAmount, "Insuficient Nfts for sell"); // lo que compra sumado a lo que se vendio tiene que ser menor al maximo
        if (clientInfo[msg.sender].nftsPresalePurchased == 0) {
            // Agrega por unica vez al array y da el rol una unica vez
            clients.push(msg.sender);
            roles.grantRole(keccak256("PRE_SALE_NFT_BUYER"), msg.sender);
        }
        clientInfo[msg.sender].nftsPresalePurchased += amountOfNfts;
        nftSold += amountOfNfts;
        uint256 amountUsdcTransfered = _swapTokens( nftPrice * amountOfNfts); //se transfieren usdc a la wallet recaudadora
        maticTransacted += nftPrice * amountOfNfts;
        usdcRaised += amountUsdcTransfered;
        uint256 surplus = msg.value - (nftPrice * amountOfNfts);
        if(surplus > 0){
            require(address(this).balance > 0, "Insuficient funds");
            (bool success, ) = msg.sender.call{value: surplus }("");
            require(success, "Forward funds fail");
        }
        emit Purchase(msg.sender, amountOfNfts, amountUsdcTransfered,nftPrice * amountOfNfts);
    }

    /// @notice Function to check the current matic price
    /// @dev External call to the price feed, the return amount is represented in 8 decimals
    /// @return Documents the price of 1 MATIC in USD
    function getLatestPrice() public view returns (uint256) {
        (
            ,
            /*uint80 roundID*/
            int256 price, /*uint startedAt*/ /*uint timeStamp*/ /*uint80 answeredInRound*/
            ,
            ,

        ) = priceFeed.latestRoundData();
        return uint256(price);
    }

    /// @notice Compute the price in matic of 1 NFT
    /// @dev uses the state variable usdPrice with the price feed to compute the price of a NFT
    /// @return uint256 the price of a NFT in matic in weis
    function computeAmount() public view returns (uint256) {
        return ((usdPrice * (10**8)) / getLatestPrice());
    }

    /* Funcion que cambia los matic que vale un NFT por USDC y los transfiere a la wallet Recaudadora 
    param:
        _nftPrice: valor de un Nft en matic expresado en weis
    global:
    usdPrice: precio de un NFT en dolares expresado en weis seteado inicialmente
     */
    function _swapTokens(uint256 _nftPrice) internal returns (uint256) {
        uint256 usdcAmount = usdPrice /10**12;//debemos convertir amountUsdcOutMin a 6 decimales para poder comparar con amounts[1] que es el monto que realmente sale
        // Amount with a % substracted
        uint256 amountUsdcOutMin = usdcAmount - ((usdcAmount * slippagePorcentual) / 1000); 
        //path for the router
        address[] memory path = new address[](2);
        path[1] = TOKENADDRESS; //usdc address
        path[0] = MATIC; //wMatic address
        //amount out is in 6 decimals
        uint256[] memory amounts = router.swapExactETHForTokens{value: _nftPrice}(amountUsdcOutMin, path, walletRecaudadora, block.timestamp);
        return amounts[1]; //monto que se transfiere
    }

    /// @notice Function to withdraw any matic stuck in the contract
    /// @dev make a low level call to send matic to the collector wallet
    function withdrawEmergency() external onlyOwner whenPaused {
        require(address(this).balance > 0, "Insuficient funds");
        (bool success, ) = walletRecaudadora.call{value: address(this).balance}("");
        require(success, "Forward funds fail");
    }

    /// @notice Function to change the price of 1 NFT
    /// @dev change the price of 1 NFT
    /// @param _newAmount new price of a NFT in USD in weis
    function setPrice(uint256 _newAmount) external onlyOwner {
        require(_newAmount > 0, "New amount is 0");
        usdPrice = _newAmount;
    }

    /// @notice Function so the owner can change the slippage
    /// @dev See slippagePorcentual state variable to check the scale
    /// @param _newSlippage value of the new slippage to make the swap
    function setSlippage(uint256 _newSlippage) external onlyOwner {
        require(_newSlippage > 0, "Slippage equal 0");
        slippagePorcentual = _newSlippage;
    }

   /// @notice Function so the owner can change the collector wallet
   /// @dev event CollectorChanged is emited
   /// @param _newWalletRecaudadora address of the new collector account
    function setWalletRecaudadora(address _newWalletRecaudadora) external onlyOwner {
        require(_newWalletRecaudadora != address(0), "Address cannot be null address");
        emit CollectorChanged(walletRecaudadora, _newWalletRecaudadora, msg.sender);
        walletRecaudadora = _newWalletRecaudadora;
    }

    /// @notice Function so the owner can change the max NFT to sell
    /// @dev the amount is a natural number
    /// @param _newAmount new amount of NFTs to sell
    function setMaxNftAmount(uint256 _newAmount) external onlyOwner {
        require(_newAmount > 0, "Amount is 0");
        maxNftAmount = _newAmount;
    }

    /// @notice Function to ask the array of clients
    /// @dev getter to the private variable clients
    /// @return address[] clients array of addresses that bougth at least 1 NFT
    function getClients() external view returns (address[] memory) {
        return clients;
    }

    //Funcion que solo puede ser llamada por el contrato de Mistery Box
    // Si no tiene nfts disponibles para reclamar retorna false, si puede reclamar un nft actualiza los contadores y devuelve true
    /// @notice This function check if a client can redeem a NFT
    /// @dev This function should be only called by a contract with MISTERY_BOX_ADDRESS role
    /// @param _beneficiary address to check if can redeem a NFT
    /// @return bool indicates of the beneficiary can or cannot redeem a NFT
    function canRedeem(address _beneficiary)
        external
        nonReentrant
        whenNotPaused
        returns (bool)
    {
        require(
            roles.hasRole(
                roles.getHashRole("MISTERY_BOX_ADDRESS"),
                msg.sender
            ),
            "Sender must have mistery box role"
        );
        if (
            clientInfo[_beneficiary].nftsPresalePurchased ==
            clientInfo[_beneficiary].claimedNfts
        ) {
            return false;
        } else {
            clientInfo[_beneficiary].claimedNfts++;
            nftsRedeemed++;
            return true;
        }
    }

    /// @notice Function to get the info of the beneficiary
    /// @dev Used to display info in a front-end
    /// @param _beneficiary address to check
    /// @return ClientInfo struct that contains the amount of NFTs that the address bougth and the amount of NFT that already redeem
    function getClientInfo(address _beneficiary)
        external
        view
        returns (ClientInfo memory)
    {
        return clientInfo[_beneficiary];
    }

    /// @notice Get the amount of nft to be redeemed
    /// @dev compute the substraction of the nfts sold and redeemed
    /// @return uint256 the amount of NFTs bougths that have not been redeemed
    function getNftsToRedeem() external view returns (uint256) {
        return nftSold - nftsRedeemed;
    }

    /// @notice Function to change the implementacion used to manage access control
    /// @dev Change the address of the access control manager
    /// @param _newRoles address of the new contract roles
    function setRoles(address _newRoles) external onlyOwner whenPaused {
        require(_newRoles != address(0),"New Roles Address cannot be 0 address");
        roles = IRoles(_newRoles);
    }

    /// @notice Set the initial value of MATIC transacted
    /// @dev Set the value of MATIC transacted after the upgrade, maticTransacted isnt in the first version of this contract
    /// @param _initialMaticTransacted value of MATIC already transacted
    function initializeMaticTransacted(uint256 _initialMaticTransacted) external onlyOwner{
        maticTransacted = _initialMaticTransacted;
    }

    /// @notice Set the initial value of USDC raised
    /// @dev Set the value of USDC raised after the upgrade, usdcRaised isnt in the first version of this contract
    /// @param _initialUsdcValue USDC already raised
    function initializeUsdcRaised(uint256 _initialUsdcValue) external onlyOwner{
        usdcRaised = _initialUsdcValue;
    }

    //Funcion para pausar
    function pause() external onlyOwner whenNotPaused {
        _pause();
    }

    //Funcion para despausar
    function unpause() external onlyOwner whenPaused {
        _unpause();
    }

    /**
     *
     * @dev See {utils/UUPSUpgradeable-_authorizeUpgrade}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     *
     */

    function _authorizeUpgrade(address _newImplementation)
        internal
        override
        whenPaused
        onlyOwner
    {}

    /**
     *
     * @dev See {utils/UUPSUpgradeable-upgradeTo}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     *
     */

    function upgradeTo(address _newImplementation)
        external
        override
        onlyOwner
        whenPaused
    {
        _authorizeUpgrade(_newImplementation);
        _upgradeToAndCallUUPS(_newImplementation, new bytes(0), false);
    }

    /**
     *
     * @dev See {utils/UUPSUpgradeable-upgradeToAndCall}.
     *
     * Requirements:
     *
     * - The caller must have ``role``'s admin role.
     * - The contract must be paused
     *
     */

    function upgradeToAndCall(address _newImplementation, bytes memory _data)
        external
        payable
        override
        onlyOwner
        whenPaused
    {
        _authorizeUpgrade(_newImplementation);
        _upgradeToAndCallUUPS(_newImplementation, _data, true);
    }
}