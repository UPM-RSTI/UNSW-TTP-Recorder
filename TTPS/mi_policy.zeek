#Script para obtener un log siguiendo los features del dataset UNSW-NB15

@load base/utils/site
@load base/utils/strings
@load base/protocols/http 
@load base/protocols/conn

module Servicio;

export {
	## El identificador del dataset logging stream
	redef enum Log::ID += { DATASET_LOG };

	## El  logging policy hook para el stream.
	global log_policy_dataset: Log::PolicyHook;

	## El tipo record que define todas la columnas del dataset log.
	type DatasetInfo: record {

		## Tiempo del primer paquete.
		ts:           time            &log;
		
		## Identificador unico para la conexion.
		uid:          string          &log;

		srcip:  addr &log &optional;		
		sport: 	port &log &optional;
		dstip:  addr &log &optional;
		dsport: port &log &optional;

		## El protocolo a nivel de transporte.
                proto:        transport_proto &log; 

		## Termino para conocer el estado de la conexion, posibles valores:
                ##
                ## * S0: Intento de conexion realizado, sin respuesta
                ##
                ## * S1: Conexion establecida y no finalizada
                ##
                ## * SF: Se establece conexion y se finaliza sin problemas
                ## 
                ## * REJ: Intento de conexion rechazado
                ##
                ## * S2: Conexion establecida y se intenta finalizar por origen
                ##   (no hay respuesta del destino).
                ##
                ## * S3: Connection established and close attempt by responder seen
                ##   (no hay respuesta del origen).
                ## 
                ## * RSTO: Conexion establecida, el origen la finaliza mandando un RST (reset).
                ##
                ## * RSTR: Destino manda un RST (reset).
                ##
                ## * RSTOS0: Origen manda un SYN seguido de un RST, entonces nunca vemos un SYN ACK del destino.
                ## 
                ## * RSTRH: Destino manda un SYN ACK seguido de un RST, entonces nunca vemos un SYN del origen.
                ##
                ## * SH: Origen manda un SYN seguido de un FIN, entonces nunca se ve un SYN ACK del destino.
                ##
                ## * SHR: Destino manda un  SYN ACK seguido de un FIN, entonces nunca se ve un SYN del origen.
                ## 
                ## * OTH: No se ve  SYN, es solo trafico intermedio
                state:   string          &log &optional;


		## Duracion de la conexion
                dur:     interval        &log &optional;

		## Numero de bytes de origen.
		sbytes:   count           &log &optional;
		
		## Numero de bytes de la respuesta.
		dbytes:   count           &log &optional;

		sttl: interval &log &optional;
		dttl: interval &log &optional;

		sloss: count &log &optional;
		dloss: count &log &optional;		

		## El protocolo de la conexion a nivel aplicacion.
                service:      string          &log &optional;

		sload: count &log &optional;
		dload: count &log &optional;

		## Numero de paquetes que envia el origen .
		spkts:     count      &log &optional;
		
		## Numero de paquetes que se envian en la respuesta
		dpkts:     count      &log &optional;
		
		trans_depth: count &log &optional;
		res_bdy_len: count &log &optional;	
};

	## Evento para poder manejar el :zeek:type:`Servicio::DatasetInfo`.
	global log_servicio_dataset: event(rec: DatasetInfo);
}

redef record connection += {
	Servicio: DatasetInfo &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Servicio::DATASET_LOG, [$columns=DatasetInfo, $ev=log_servicio_dataset, $path="my_log", $policy=log_policy_dataset]);
	}

function conn_state(c: connection, trans: transport_proto): string
	{
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = os == TCP_INACTIVE || os == TCP_PARTIAL;
	local r_inactive = rs == TCP_INACTIVE || rs == TCP_PARTIAL;

	if ( trans == tcp )
		{
		if ( rs == TCP_RESET )
			{
			if ( os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT ||
			     (os == TCP_RESET &&
			      c$orig$size == 0 && c$resp$size == 0) )
				return "REJ";
			else if ( o_inactive )
				return "RSTRH";
			else
				return "RSTR";
			}
		else if ( os == TCP_RESET )
			{
			if ( r_inactive )
				{
				if ( /\^?S[^HAFGIQ]*R.*/ == c$history )
					return "RSTOS0";

				return "OTH";
				}

			return "RSTO";
			}
		else if ( rs == TCP_CLOSED && os == TCP_CLOSED )
			return "SF";
		else if ( os == TCP_CLOSED )
			return r_inactive ? "SH" : "S2";
		else if ( rs == TCP_CLOSED )
			return o_inactive ? "SHR" : "S3";
		else if ( os == TCP_SYN_SENT && rs == TCP_INACTIVE )
			return "S0";
		else if ( os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED )
			return "S1";
		else
			return "OTH";
		}

	else if ( trans == udp )
		{
		if ( os == UDP_ACTIVE )
			return rs == UDP_ACTIVE ? "SF" : "S0";
		else
			return rs == UDP_ACTIVE ? "SHR" : "OTH";
		}

	else
		return "OTH";
	}

## Rellenar las columnas del log con la conexion
function set_conn(c: connection, eoc: bool)
	{
	if ( ! c?$Servicio )
		{
		local p = get_port_transport_proto(c$id$resp_p);
		c$Servicio = DatasetInfo($ts=c$start_time, $uid=c$uid,$proto=p);
		}

	c$Servicio$srcip=c$id$orig_h;
	c$Servicio$sport=c$id$orig_p;
	c$Servicio$dstip=c$id$resp_h;
	c$Servicio$dsport=c$id$resp_p;
	if ( eoc )
		{
		if ( c$duration > 0secs )
			{
			c$Servicio$dur=c$duration;
			c$Servicio$sbytes=c$orig$size;
			c$Servicio$dbytes=c$resp$size;
			}
		if ( c$orig?$num_pkts )
			{
			c$Servicio$spkts = c$orig$num_pkts;
			c$Servicio$dpkts = c$resp$num_pkts;
			}

		if ( |c$service| > 0 )
			c$Servicio$service=to_lower(join_string_set(c$service, ","));

		if( c?$http_state)
			{
			print "hola";
			c$Servicio$trans_depth=c$http$trans_depth;
			c$Servicio$res_bdy_len=c$http$response_body_len;
			}
		if( ! c?$http_state)
			{
			print "adios";
			c$Servicio$trans_depth=0;
			c$Servicio$res_bdy_len=0;
			}
		c$Servicio$state=conn_state(c, get_port_transport_proto(c$id$resp_p));
	}	
	}

event content_gap(c: connection, is_orig: bool, seq: count, length: count) &priority=5
	{
	set_conn(c, F);
	}

event tunnel_changed(c: connection, e: EncapsulatingConnVector) &priority=5
	{
	set_conn(c, F);
	}

event connection_state_remove(c: connection) &priority=5
	{
	set_conn(c, T);
	}

event connection_state_remove(c: connection) &priority=-5
	{
	Log::write(Servicio::DATASET_LOG, c$Servicio);
	}

