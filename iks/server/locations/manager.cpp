#include "manager.h"

#include <functional>

#include "locations/welcome/welcome.h"
#include "locations/proxy/proxy.h"
#include "locations/szbase/szbase.h"
#include "locations/protocol_location.h"

LocationsMgr::LocationsMgr()
{
	loc_factory.register_location
		<ProxyLoc>( "local" , "127.0.0.1" , 9002 );
	loc_factory.register_location
		<SzbaseLocation>( "gcwp" , "gcwp" );
}

LocationsMgr::~LocationsMgr()
{
}

void LocationsMgr::on_new_connection( Connection* con )
{
	new_location( std::make_shared<ProtocolLocation>( std::make_shared<WelcomeProt>(loc_factory) , con ) );
}

void LocationsMgr::on_disconnected( Connection* con )
{
	auto itr = locations.find( con );
	if( itr != locations.end() )
		locations.erase( itr );
}

void LocationsMgr::new_location( Location::ptr nloc , std::weak_ptr<Location> oloc_w )
{
	auto oloc = oloc_w.lock();

	if( oloc )
		nloc->swap_connection( *oloc );

	locations[ nloc->connection ] = nloc;

	nloc->on_location_request(
		std::bind(
			&LocationsMgr::new_location, this,
			std::placeholders::_1 , std::weak_ptr<Location>(nloc) ) );
}
